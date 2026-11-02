#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>

#include <libubox/utils.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_UBUS_TIMEOUT	500

struct assoc_ctx {
	struct mesh_assoc_idx *idx;
	uint8_t band;
	const char *enc;
};

static void assoc_bytes(struct blob_attr *t, uint64_t *out)
{
	static const struct blobmsg_policy bp = { "bytes", BLOBMSG_TYPE_INT64 };
	struct blob_attr *v = NULL;

	if (!t)
		return;

	blobmsg_parse(&bp, 1, &v, blobmsg_data(t), blobmsg_data_len(t));
	if (v)
		*out = blobmsg_get_u64(v);
}

static uint32_t assoc_rate(struct blob_attr *t)
{
	static const struct blobmsg_policy rp = { "rate", BLOBMSG_TYPE_INT32 };
	struct blob_attr *v = NULL;

	blobmsg_parse(&rp, 1, &v, blobmsg_data(t), blobmsg_data_len(t));

	return v ? blobmsg_get_u32(v) : 0;
}

static void assoc_phy(struct blob_attr *rate, struct mesh_assoc *a)
{
	enum { R_RATE, R_MHZ, R_NSS, R_HT, R_VHT, R_HE, __R_MAX };
	static const struct blobmsg_policy rp[__R_MAX] = {
		[R_RATE] = { "rate", BLOBMSG_TYPE_INT32 },
		[R_MHZ] = { "mhz", BLOBMSG_TYPE_INT32 },
		[R_NSS] = { "nss", BLOBMSG_TYPE_INT32 },
		[R_HT] = { "ht", BLOBMSG_TYPE_INT8 },
		[R_VHT] = { "vht", BLOBMSG_TYPE_INT8 },
		[R_HE] = { "he", BLOBMSG_TYPE_INT8 },
	};
	struct blob_attr *tb[__R_MAX];
	const char *std;

	blobmsg_parse(rp, __R_MAX, tb, blobmsg_data(rate), blobmsg_data_len(rate));

	if (tb[R_RATE])
		a->rate = blobmsg_get_u32(tb[R_RATE]);
	if (tb[R_MHZ])
		a->width = blobmsg_get_u32(tb[R_MHZ]);
	if (tb[R_NSS])
		a->nss = blobmsg_get_u32(tb[R_NSS]);

	if (tb[R_HE] && blobmsg_get_u8(tb[R_HE]))
		std = "11ax";
	else if (tb[R_VHT] && blobmsg_get_u8(tb[R_VHT]))
		std = "11ac";
	else if (tb[R_HT] && blobmsg_get_u8(tb[R_HT]))
		std = "11n";
	else
		std = a->band == BAND_LOW ? "11g" : "11a";

	strncpy(a->std, std, sizeof(a->std) - 1);
}

static void assoc_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy lp = { "results", BLOBMSG_TYPE_ARRAY };
	enum { A_MAC, A_RX, A_TX, A_CONNECTED, A_INACTIVE, __A_MAX };
	static const struct blobmsg_policy ap[__A_MAX] = {
		[A_MAC] = { "mac", BLOBMSG_TYPE_STRING },
		[A_RX] = { "rx", BLOBMSG_TYPE_TABLE },
		[A_TX] = { "tx", BLOBMSG_TYPE_TABLE },
		[A_CONNECTED] = { "connected_time", BLOBMSG_TYPE_INT32 },
		[A_INACTIVE] = { "inactive", BLOBMSG_TYPE_INT32 },
	};
	struct assoc_ctx *ctx = req->priv;
	struct blob_attr *results = NULL, *cur;
	int rem;

	blobmsg_parse(&lp, 1, &results, blob_data(msg), blob_len(msg));
	if (!results)
		return;

	blobmsg_for_each_attr(cur, results, rem) {
		struct blob_attr *tb[__A_MAX];
		struct ether_addr *ea;
		struct mesh_assoc *a;

		if (ctx->idx->n >= MESH_ASSOC_MAX)
			break;

		blobmsg_parse(ap, __A_MAX, tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[A_MAC])
			continue;

		ea = ether_aton(blobmsg_get_string(tb[A_MAC]));
		if (!ea)
			continue;

		a = &ctx->idx->e[ctx->idx->n++];
		memset(a, 0, sizeof(*a));
		memcpy(a->addr, ea->ether_addr_octet, 6);
		a->band = ctx->band;
		if (tb[A_CONNECTED])
			a->connected = blobmsg_get_u32(tb[A_CONNECTED]);
		if (tb[A_INACTIVE])
			a->inactive = blobmsg_get_u32(tb[A_INACTIVE]);
		if (ctx->enc)
			strncpy(a->enc, ctx->enc, sizeof(a->enc) - 1);
		if (tb[A_TX])
			assoc_phy(tb[A_TX], a);
		if (tb[A_RX])
			a->rx_rate = assoc_rate(tb[A_RX]);
		assoc_bytes(tb[A_RX], &a->rx_bytes);
		assoc_bytes(tb[A_TX], &a->tx_bytes);
	}
}

static void info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy ep = { "encryption", BLOBMSG_TYPE_TABLE };
	static const struct blobmsg_policy wp[2] = {
		{ "wpa", BLOBMSG_TYPE_ARRAY },
		{ "enabled", BLOBMSG_TYPE_INT8 },
	};
	struct blob_attr *enc = NULL, *tb[2], *cur;
	char *out = req->priv;
	int rem, max = 0, min = 0;

	blobmsg_parse(&ep, 1, &enc, blob_data(msg), blob_len(msg));
	if (!enc)
		return;

	blobmsg_parse(wp, 2, tb, blobmsg_data(enc), blobmsg_data_len(enc));
	if (tb[1] && !blobmsg_get_u8(tb[1]))
		return;

	if (tb[0])
		blobmsg_for_each_attr(cur, tb[0], rem) {
			int v = 0;

			switch (blobmsg_type(cur)) {
			case BLOBMSG_TYPE_INT32: v = blobmsg_get_u32(cur); break;
			case BLOBMSG_TYPE_INT16: v = blobmsg_get_u16(cur); break;
			case BLOBMSG_TYPE_INT8: v = blobmsg_get_u8(cur); break;
			}

			if (v > max)
				max = v;
			if (v && (!min || v < min))
				min = v;
		}

	if (max >= 3)
		strcpy(out, min == 2 ? "WPA2/WPA3" : "WPA3");
	else
		strcpy(out, max == 2 ? "WPA2" : max == 1 ? "WPA" : "");
}

bool mesh_parent_mac(uint8_t *out)
{
	char line[256];
	FILE *f;
	bool found = false;

	if (mesh.role != MESH_NODE || !mesh.controller_addr[0])
		return false;

	f = fopen("/proc/net/arp", "r");
	if (!f)
		return false;

	while (!found && fgets(line, sizeof(line), f)) {
		char ip[64], type[16], flags[16], hw[32];
		struct ether_addr ea;

		if (sscanf(line, "%63s %15s %15s %31s", ip, type, flags, hw) != 4)
			continue;

		if (strcmp(ip, mesh.controller_addr) || !strcmp(flags, "0x0"))
			continue;

		if (!ether_aton_r(hw, &ea))
			continue;

		memcpy(out, ea.ether_addr_octet, 6);
		found = true;
	}

	fclose(f);

	return found;
}

/*
 * The interface label says what the BSS offers; in a mixed WPA2/WPA3 BSS the
 * client's own (re)association request says which AKM it actually took.
 */
static const char *akm_label(const uint8_t *ie, size_t len)
{
	static const uint8_t rsn_oui[3] = { 0x00, 0x0f, 0xac };
	static const uint8_t wpa_oui[4] = { 0x00, 0x50, 0xf2, 0x01 };
	const char *label = NULL;

	while (len >= 2 && len >= 2u + ie[1]) {
		const uint8_t *p = ie + 2;
		size_t l = ie[1];
		unsigned int i, n;

		if (ie[0] == 48 && l >= 2) {
			/* version, group cipher, pairwise count + list, akm count + list */
			if (l < 8)
				goto next;
			n = p[6] | p[7] << 8;
			if (l < 10u + 4 * n)
				goto next;
			p += 8 + 4 * n;
			n = p[0] | p[1] << 8;
			l = ie[1] - (p - (ie + 2)) - 2;
			p += 2;
			if (l < 4u * n)
				goto next;

			for (i = 0; i < n; i++, p += 4) {
				if (memcmp(p, rsn_oui, 3))
					continue;

				switch (p[3]) {
				case 8: case 9: case 24: case 25:
					return "WPA3";
				case 18:
					label = "OWE";
					break;
				default:
					if (!label)
						label = "WPA2";
					break;
				}
			}
		} else if (ie[0] == 221 && l >= 4 && !memcmp(p, wpa_oui, 4) && !label) {
			label = "WPA";
		}
next:
		len -= 2 + ie[1];
		ie += 2 + ie[1];
	}

	return label;
}

static void sta_ies_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy ip = { "assoc_ie", BLOBMSG_TYPE_STRING };
	struct blob_attr *v = NULL;
	struct mesh_assoc *a = req->priv;
	uint8_t ie[1024];
	const char *label;
	int len;

	blobmsg_parse(&ip, 1, &v, blob_data(msg), blob_len(msg));
	if (!v)
		return;

	len = b64_decode(blobmsg_get_string(v), ie, sizeof(ie));
	if (len <= 0)
		return;

	label = akm_label(ie, len);
	if (label)
		snprintf(a->enc, sizeof(a->enc), "%s", label);
}

/*
 * The AKM of an association does not change until the station reconnects;
 * a connected time that went backwards means a new association.
 */
struct enc_memo {
	uint8_t addr[6];
	char ifname[16];
	uint32_t connected;
	char enc[16];
};

static struct enc_memo enc_memo[MESH_ASSOC_MAX];
static unsigned int enc_memo_next;

static struct enc_memo *enc_memo_find(const struct roam_bss *bss, const struct mesh_assoc *a)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(enc_memo); i++)
		if (!memcmp(enc_memo[i].addr, a->addr, 6) &&
		    !strcmp(enc_memo[i].ifname, bss->ifname))
			return &enc_memo[i];

	return NULL;
}

static void assoc_refine_enc(struct roam_bss *bss, struct mesh_assoc *a)
{
	static struct blob_buf sb;
	struct enc_memo *m;
	char mac[18];

	if (!bss->obj_id)
		return;

	m = enc_memo_find(bss, a);
	if (m && m->connected <= a->connected) {
		m->connected = a->connected;
		if (m->enc[0])
			snprintf(a->enc, sizeof(a->enc), "%s", m->enc);
		return;
	}

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 a->addr[0], a->addr[1], a->addr[2], a->addr[3], a->addr[4], a->addr[5]);

	blob_buf_init(&sb, 0);
	blobmsg_add_string(&sb, "address", mac);
	if (ubus_invoke(ubus_ctx, bss->obj_id, "get_sta_ies", sb.head, sta_ies_cb, a,
			MESH_UBUS_TIMEOUT))
		return;

	if (!m) {
		m = &enc_memo[enc_memo_next];
		enc_memo_next = (enc_memo_next + 1) % ARRAY_SIZE(enc_memo);
	}

	memcpy(m->addr, a->addr, 6);
	snprintf(m->ifname, sizeof(m->ifname), "%.15s", bss->ifname);
	m->connected = a->connected;
	snprintf(m->enc, sizeof(m->enc), "%s", a->enc);
}

void mesh_assoc_collect(struct mesh_assoc_idx *idx)
{
	static struct blob_buf ab;
	struct roam_bss *bss;
	uint32_t iwinfo_id;

	idx->n = 0;
	if (ubus_lookup_id(ubus_ctx, "iwinfo", &iwinfo_id))
		return;

	list_for_each_entry(bss, &roam_bss_list, list) {
		struct assoc_ctx ctx = { .idx = idx, .band = bss->band, .enc = NULL };
		char enc[16] = "";
		unsigned int first = idx->n, i;

		if (!bss->active)
			continue;

		if (mesh.backhaul_ssid[0] && !strcmp(bss->ssid, mesh.backhaul_ssid))
			continue;

		blob_buf_init(&ab, 0);
		blobmsg_add_string(&ab, "device", bss->ifname);

		ubus_invoke(ubus_ctx, iwinfo_id, "info", ab.head, info_cb, enc, MESH_UBUS_TIMEOUT);
		ctx.enc = enc[0] ? enc : NULL;
		ubus_invoke(ubus_ctx, iwinfo_id, "assoclist", ab.head, assoc_cb, &ctx, MESH_UBUS_TIMEOUT);

		if (strstr(enc, "WPA3"))
			for (i = first; i < idx->n; i++)
				assoc_refine_enc(bss, &idx->e[i]);
	}
}

void mesh_assoc_blob(struct blob_buf *b, const struct mesh_assoc *a)
{
	if (a->inactive)
		blobmsg_add_u32(b, "inactive", a->inactive);

	if (a->wired) {
		blobmsg_add_u8(b, "wired", 1);
		return;
	}

	if (a->rate)
		blobmsg_add_u32(b, "rate", a->rate);
	if (a->rx_rate)
		blobmsg_add_u32(b, "rx_rate", a->rx_rate);
	if (a->std[0])
		blobmsg_add_string(b, "std", a->std);
	if (a->width)
		blobmsg_add_u32(b, "width", a->width);
	if (a->nss)
		blobmsg_add_u32(b, "nss", a->nss);
	if (a->connected)
		blobmsg_add_u32(b, "connected", a->connected);
	if (a->enc[0])
		blobmsg_add_string(b, "encryption", a->enc);
	if (a->rx_bytes)
		blobmsg_add_u64(b, "rx_bytes", a->rx_bytes);
	if (a->tx_bytes)
		blobmsg_add_u64(b, "tx_bytes", a->tx_bytes);
}
