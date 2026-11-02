#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_UBUS_TIMEOUT	500

static void blob_keep_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr **out = req->priv;

	free(*out);
	*out = blob_memdup(msg);
}

static struct blob_attr *ubus_fetch(uint32_t id, const char *method, struct blob_attr *args)
{
	struct blob_attr *out = NULL;

	ubus_invoke(ubus_ctx, id, method, args, blob_keep_cb, &out, MESH_UBUS_TIMEOUT);

	return out;
}

static struct blob_attr *msg_field(struct blob_attr *msg, const char *name, int type)
{
	struct blobmsg_policy p = { name, type };
	struct blob_attr *v = NULL;

	if (msg)
		blobmsg_parse(&p, 1, &v, blob_data(msg), blob_len(msg));

	return v;
}

static struct blob_attr *table_field(struct blob_attr *t, const char *name, int type)
{
	struct blobmsg_policy p = { name, type };
	struct blob_attr *v = NULL;

	if (t)
		blobmsg_parse(&p, 1, &v, blobmsg_data(t), blobmsg_data_len(t));

	return v;
}

/*
 * One phy may serve several wifi-devices (MT7992: 2.4 and 5 GHz on phy0), and
 * iwinfo asked by the device name then answers for whichever band it finds
 * first. Ask by the first interface of the device instead.
 */
static bool radio_state(struct blob_attr *ws, const char *dev, char *ifname, size_t len)
{
	struct blob_attr *t = msg_field(ws, dev, BLOBMSG_TYPE_TABLE);
	struct blob_attr *ifs = table_field(t, "interfaces", BLOBMSG_TYPE_ARRAY);
	struct blob_attr *up = table_field(t, "up", BLOBMSG_TYPE_BOOL);
	struct blob_attr *cur;
	int rem;

	snprintf(ifname, len, "%s", dev);

	if (!t)
		return true;

	if (ifs)
		blobmsg_for_each_attr(cur, ifs, rem) {
			struct blob_attr *n = table_field(cur, "ifname", BLOBMSG_TYPE_STRING);

			if (n) {
				snprintf(ifname, len, "%s", blobmsg_get_string(n));
				break;
			}
		}

	return up && blobmsg_get_bool(up);
}

/* DFS channels are 52-64 and 100-144 in every regulatory domain; iwinfo has no flag for it. */
bool mesh_channel_dfs(int channel)
{
	return (channel >= 52 && channel <= 64) || (channel >= 100 && channel <= 144);
}

static int htmode_width(const char *htmode)
{
	while (htmode && *htmode && !isdigit((unsigned char)*htmode))
		htmode++;

	return htmode && *htmode ? atoi(htmode) : 20;
}

/*
 * The width the radio really runs at: hostapd falls back to 20 MHz when the
 * secondary channel is not usable, while htmode still says HE40.
 */
static int radio_width_actual(int channel, int center)
{
	int d;

	if (!channel || !center)
		return 0;

	d = abs(center - channel);

	return d == 0 ? 20 : d == 2 ? 40 : d == 6 ? 80 : d == 14 ? 160 : 0;
}

const char *const mesh_radio_opts[__MESH_RADIO_MAX] = {
	[MESH_RADIO_TX24] = "txpower_24",
	[MESH_RADIO_TX5] = "txpower_5",
	[MESH_RADIO_CH24] = "channel_24",
	[MESH_RADIO_CH5] = "channel_5",
	[MESH_RADIO_W24] = "width_24",
	[MESH_RADIO_W5] = "width_5",
};

/* 0 always means "not managed by roamd"; DFS channels are not offered */
bool mesh_radio_value_ok(unsigned int opt, int v)
{
	if (!v)
		return true;

	switch (opt) {
	case MESH_RADIO_TX24:
	case MESH_RADIO_TX5:
		return v > 0 && v <= MESH_TXPOWER_MAX;
	case MESH_RADIO_CH24:
		return v >= 1 && v <= 13;
	case MESH_RADIO_CH5:
		return (v >= 36 && v <= 48 && v % 4 == 0) || (v >= 149 && v <= 177 && (v - 149) % 4 == 0);
	case MESH_RADIO_W24:
		return v == 20 || v == 40;
	case MESH_RADIO_W5:
		return v == 20 || v == 40 || v == 80 || v == 160;
	}

	return false;
}

/*
 * htmode for the wanted width, keeping the standard the radio runs now
 * (HT/VHT/HE/EHT); VHT does not exist on 2.4 GHz and HT has no 80/160 MHz.
 */
static void htmode_for(const char *cur, uint8_t band, int width, char *out, size_t len)
{
	const char *std = "HT";

	if (cur && !strncmp(cur, "EHT", 3))
		std = "EHT";
	else if (cur && !strncmp(cur, "HE", 2))
		std = "HE";
	else if (cur && !strncmp(cur, "VHT", 3))
		std = "VHT";

	if (band == MESH_BAND_24 && !strcmp(std, "VHT"))
		std = "HT";
	if (width > 40 && !strcmp(std, "HT"))
		std = "VHT";

	snprintf(out, len, "%s%d", std, width);
}

/*
 * Per-band channel and width into every wifi-device of that band. A cleared
 * channel removes only what roamd wrote (the radio goes back to auto); a
 * cleared width leaves htmode as it is, since without htmode OpenWrt turns
 * HT off. keep_channel_band: bands whose channel follows the uplink parent.
 */
bool mesh_channel_apply(const int *channel, const int *width, const int *prev_channel,
			uint8_t keep_channel_band)
{
	struct uci_session u;
	struct uci_element *e;
	bool changed;

	if (!uci_session_open(&u, "wireless"))
		return false;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		enum roam_band band;
		char value[16];
		uint8_t bit;

		if (strcmp(s->type, "wifi-device"))
			continue;

		bit = mesh_radio_band(u.ctx, u.pkg, s->e.name);
		if (!bit)
			continue;

		band = mesh_band_from_bit(bit);

		if (!(keep_channel_band & bit)) {
			if (channel[band] > 0) {
				snprintf(value, sizeof(value), "%d", channel[band]);
				uci_session_set(&u, s->e.name, "channel", value);
			} else if (prev_channel && prev_channel[band] > 0) {
				uci_session_delete(&u, s->e.name, "channel");
			}
		}

		if (width[band] > 0) {
			htmode_for(uci_lookup_option_string(u.ctx, s, "htmode"), bit, width[band],
				   value, sizeof(value));
			uci_session_set(&u, s->e.name, "htmode", value);
		}
	}

	changed = u.dirty;
	uci_session_close(&u);

	if (changed)
		roam_log(ROAM_L_INFO, "mesh: channels updated (2.4 GHz: %d/%d MHz, 5 GHz: %d/%d MHz)",
			 channel[BAND_LOW], width[BAND_LOW], channel[BAND_HIGH], width[BAND_HIGH]);

	return changed;
}

/*
 * The channels the current region allows. Only presence and DFS are kept:
 * mt76 reports per-channel flags (no_ir, no_ht40+, restricted) that change
 * between calls and contradict iw phy, so they are not usable.
 */
static void radio_freqlist(struct blob_buf *b, struct blob_attr *msg, uint8_t band)
{
	struct blob_attr *list = msg_field(msg, "results", BLOBMSG_TYPE_ARRAY), *cur;
	int want = band == MESH_BAND_5 ? 5 : 2;
	void *arr;
	int rem;

	if (!list)
		return;

	arr = blobmsg_open_array(b, "freqlist");

	blobmsg_for_each_attr(cur, list, rem) {
		struct blob_attr *bnd = table_field(cur, "band", BLOBMSG_TYPE_INT32);
		struct blob_attr *ch = table_field(cur, "channel", BLOBMSG_TYPE_INT32);
		void *t;

		if (!ch || (bnd && (int)blobmsg_get_u32(bnd) != want))
			continue;

		t = blobmsg_open_table(b, NULL);
		blobmsg_add_u32(b, "channel", blobmsg_get_u32(ch));
		if (mesh_channel_dfs(blobmsg_get_u32(ch)))
			blobmsg_add_u8(b, "dfs", 1);
		blobmsg_close_table(b, t);
	}

	blobmsg_close_array(b, arr);
}

static int radio_txpowerlist(struct blob_buf *b, struct blob_attr *msg)
{
	struct blob_attr *list = msg_field(msg, "results", BLOBMSG_TYPE_ARRAY), *cur;
	int max = -1, rem;
	void *arr;

	if (!list)
		return max;

	arr = blobmsg_open_array(b, "txpowerlist");

	blobmsg_for_each_attr(cur, list, rem) {
		struct blob_attr *v = table_field(cur, "dbm", BLOBMSG_TYPE_INT32);
		int dbm;

		if (!v)
			continue;

		dbm = blobmsg_get_u32(v);
		blobmsg_add_u32(b, NULL, (uint32_t)dbm);
		if (dbm > max)
			max = dbm;
	}

	blobmsg_close_array(b, arr);

	return max;
}

/*
 * One entry per wifi-device: band, configured and actual power, channel,
 * width and region, the power steps and the channels the radio allows.
 */
void mesh_radios_dump(struct blob_buf *b, const char *name)
{
	static struct blob_buf ab;
	struct blob_attr *ws = NULL;
	struct uci_session u;
	struct uci_element *e;
	uint32_t iwinfo_id, wid;
	bool have_iwinfo;
	void *arr;

	if (!uci_session_open(&u, "wireless"))
		return;

	have_iwinfo = !ubus_lookup_id(ubus_ctx, "iwinfo", &iwinfo_id);
	if (!ubus_lookup_id(ubus_ctx, "network.wireless", &wid))
		ws = ubus_fetch(wid, "status", NULL);

	arr = blobmsg_open_array(b, name);

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *set = uci_lookup_option_string(u.ctx, s, "txpower");
		const char *disabled = uci_lookup_option_string(u.ctx, s, "disabled");
		const char *opt;
		struct blob_attr *info = NULL, *txl = NULL, *frl = NULL, *v;
		char ifname[IFNAMSIZ + 8];
		int max = -1;
		uint8_t band;
		bool up;
		void *t;

		if (strcmp(s->type, "wifi-device"))
			continue;

		band = mesh_radio_band(u.ctx, u.pkg, s->e.name);
		if (!band)
			continue;

		up = radio_state(ws, s->e.name, ifname, sizeof(ifname));

		if (have_iwinfo) {
			blob_buf_init(&ab, 0);
			blobmsg_add_string(&ab, "device", ifname);
			info = ubus_fetch(iwinfo_id, "info", ab.head);
			txl = ubus_fetch(iwinfo_id, "txpowerlist", ab.head);
			frl = ubus_fetch(iwinfo_id, "freqlist", ab.head);
		}

		t = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "radio", s->e.name);
		blobmsg_add_string(b, "band", band == MESH_BAND_5 ? "5" : "2.4");
		blobmsg_add_u32(b, "txpower_set", set ? (uint32_t)atoi(set) : 0);
		if (disabled && roam_uci_bool(disabled))
			blobmsg_add_u8(b, "disabled", 1);
		blobmsg_add_u8(b, "up", up);

		opt = uci_lookup_option_string(u.ctx, s, "channel");
		blobmsg_add_string(b, "channel_set", opt ? opt : "auto");
		opt = uci_lookup_option_string(u.ctx, s, "htmode");
		blobmsg_add_string(b, "htmode_set", opt ? opt : "");
		opt = uci_lookup_option_string(u.ctx, s, "country");
		blobmsg_add_string(b, "country_set", opt ? opt : "");

		if (up && (v = msg_field(info, "txpower", BLOBMSG_TYPE_INT32)))
			blobmsg_add_u32(b, "txpower", blobmsg_get_u32(v));
		if (up && (v = msg_field(info, "channel", BLOBMSG_TYPE_INT32)))
			blobmsg_add_u32(b, "channel", blobmsg_get_u32(v));
		if (up && (v = msg_field(info, "htmode", BLOBMSG_TYPE_STRING))) {
			struct blob_attr *ch = msg_field(info, "channel", BLOBMSG_TYPE_INT32);
			struct blob_attr *cc = msg_field(info, "center_chan1", BLOBMSG_TYPE_INT32);
			int real = radio_width_actual(ch ? (int)blobmsg_get_u32(ch) : 0,
						      cc ? (int)blobmsg_get_u32(cc) : 0);

			blobmsg_add_string(b, "htmode", blobmsg_get_string(v));
			blobmsg_add_u32(b, "width", (uint32_t)htmode_width(blobmsg_get_string(v)));
			if (real)
				blobmsg_add_u32(b, "width_actual", (uint32_t)real);
		}
		if ((v = msg_field(info, "country", BLOBMSG_TYPE_STRING)))
			blobmsg_add_string(b, "country", blobmsg_get_string(v));
		if ((v = msg_field(info, "htmodes", BLOBMSG_TYPE_ARRAY)))
			blobmsg_add_field(b, BLOBMSG_TYPE_ARRAY, "htmodes",
					  blobmsg_data(v), blobmsg_data_len(v));

		max = radio_txpowerlist(b, txl);
		if (max >= 0)
			blobmsg_add_u32(b, "txpower_max", (uint32_t)max);
		radio_freqlist(b, frl, band);

		blobmsg_close_table(b, t);

		free(info);
		free(txl);
		free(frl);
	}

	blobmsg_close_array(b, arr);
	uci_session_close(&u);
	free(ws);
}

bool mesh_country_valid(const char *c)
{
	if (!c)
		return false;

	if (!c[0] || !strcmp(c, "00"))
		return true;

	return strlen(c) == 2 && isupper((unsigned char)c[0]) && isupper((unsigned char)c[1]);
}

/*
 * The region the nodes follow: the one chosen in roamd.mesh.country, or, when
 * none is chosen, the one the controller radios are set to.
 */
const char *mesh_country_effective(void)
{
	static char out[sizeof(mesh.country)];
	struct uci_session u;
	struct uci_element *e;

	if (mesh.country[0])
		return mesh.country;

	out[0] = 0;
	if (!uci_session_open(&u, "wireless"))
		return out;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *c;

		if (strcmp(s->type, "wifi-device") || !mesh_radio_band(u.ctx, u.pkg, s->e.name))
			continue;

		c = uci_lookup_option_string(u.ctx, s, "country");
		if (c && c[0] && mesh_country_valid(c)) {
			snprintf(out, sizeof(out), "%s", c);
			break;
		}
	}

	uci_session_close(&u);

	return out;
}

/*
 * Write the regulatory country into every wifi-device. Empty means "leave
 * the radios alone": the option is removed only if roamd set it before.
 */
bool mesh_country_apply(const char *want, const char *prev)
{
	struct uci_session u;
	struct uci_element *e;
	bool changed;

	if (!mesh_country_valid(want) || !uci_session_open(&u, "wireless"))
		return false;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "wifi-device") || !mesh_radio_band(u.ctx, u.pkg, s->e.name))
			continue;

		if (want[0])
			uci_session_set(&u, s->e.name, "country", want);
		else if (prev && prev[0])
			uci_session_delete(&u, s->e.name, "country");
	}

	changed = u.dirty;
	uci_session_close(&u);

	if (changed)
		roam_log(ROAM_L_INFO, "mesh: regulatory region %s", want[0] ? want : "left to the device");

	return changed;
}

/*
 * Write the per-band txpower into every wifi-device of that band. 0 means
 * "leave the radio alone": the option is removed only if we set it before
 * (prev), so a value the user typed by hand on the device survives.
 */
bool mesh_txpower_apply(const int *want, const int *prev)
{
	struct uci_session u;
	struct uci_element *e;
	bool changed;

	if (!uci_session_open(&u, "wireless"))
		return false;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		enum roam_band band;
		char value[12];
		uint8_t bit;

		if (strcmp(s->type, "wifi-device"))
			continue;

		bit = mesh_radio_band(u.ctx, u.pkg, s->e.name);
		if (!bit)
			continue;

		band = mesh_band_from_bit(bit);

		if (want[band] > 0) {
			snprintf(value, sizeof(value), "%d", want[band]);
			uci_session_set(&u, s->e.name, "txpower", value);
		} else if (prev && prev[band] > 0) {
			uci_session_delete(&u, s->e.name, "txpower");
		}
	}

	changed = u.dirty;
	uci_session_close(&u);

	if (changed)
		roam_log(ROAM_L_INFO, "mesh: transmit power updated (2.4 GHz: %s, 5 GHz: %s)",
			 want[BAND_LOW] > 0 ? "set" : "default",
			 want[BAND_HIGH] > 0 ? "set" : "default");

	return changed;
}

void mesh_backhaul_bss_set(bool up)
{
	struct uci_session u;
	struct uci_element *e;
	bool changed;

	if (!uci_session_open(&u, "wireless"))
		return;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		char name[MESH_NAME_MAX];

		if (strcmp(s->type, "wifi-device"))
			continue;

		snprintf(name, sizeof(name), "%s%s", MESH_BH_PREFIX, s->e.name);

		if (!uci_lookup_section(u.ctx, u.pkg, name) &&
		    (!up || !uci_session_add(&u, "wifi-iface", name)))
			continue;

		if (!up) {
			uci_session_set(&u, name, "disabled", "1");
			continue;
		}

		uci_session_set(&u, name, "device", s->e.name);
		uci_session_set(&u, name, "mode", "ap");
		uci_session_set(&u, name, "network", "lan");
		uci_session_set(&u, name, "hidden", "1");
		uci_session_set(&u, name, "wds", "1");
		uci_session_set(&u, name, "encryption", "psk2");
		uci_session_set(&u, name, "ssid", mesh.backhaul_ssid);
		uci_session_set(&u, name, "key", mesh.backhaul_key);
		uci_session_set(&u, name, "disabled", "0");
	}

	changed = u.dirty;
	uci_session_close(&u);

	if (changed)
		roam_network_reload("backhaul access point");
}
