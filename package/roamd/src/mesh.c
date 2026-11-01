#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <libubox/uloop.h>

#include <dlfcn.h>
#include <libubox/ustream-ssl.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_FT_WATCH_INTERVAL	60000
#define MESH_WPAD_INIT		"/etc/init.d/wpad"
#define MESH_RRB_PROTO		"88b7"

#define MESH_UBUS_TIMEOUT	500
#define MESH_DEPS_FIRST		5000
#define MESH_DEPS_RETRY		300000

static struct uloop_timeout deps_timer;
static bool deps_ready;
static void deps_done(struct mesh_task *task, int ret);
static struct mesh_task deps_job = { .done = deps_done };

void mesh_dir_ensure(const char *path)
{
	mkdir(MESH_RUN_DIR, 0755);

	if (path && strcmp(path, MESH_RUN_DIR))
		mkdir(path, 0755);
}

struct ustream_ssl_ctx *mesh_ssl_context(const struct ustream_ssl_ops **ops)
{
	static const struct ustream_ssl_ops *cached;

	if (!cached) {
		void *dl = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);

		cached = dl ? dlsym(dl, "ustream_ssl_ops") : NULL;

		if (!cached)
			return NULL;
	}

	*ops = cached;

	return cached->context_new(false);
}

pid_t mesh_spawn_argv(char *const argv[])
{
	pid_t pid = fork();

	if (pid == 0) {
		int fd = open("/dev/null", O_WRONLY);

		setpgid(0, 0);

		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}

		execv(argv[0], argv);
		_exit(127);
	}

	return pid;
}

pid_t mesh_spawn(const char *script, const char *arg1, const char *arg2)
{
	char *argv[5] = { "/bin/sh", (char *)script, (char *)arg1, (char *)arg2, NULL };

	return mesh_spawn_argv(argv);
}

static void mesh_task_done(struct uloop_process *p, int ret)
{
	struct mesh_task *task = container_of(p, struct mesh_task, proc);

	task->busy = false;
	task->proc.pid = 0;

	if (task->done)
		task->done(task, ret);
}

bool mesh_task_run(struct mesh_task *task, char *const argv[])
{
	pid_t pid;

	if (task->busy)
		return false;

	pid = mesh_spawn_argv(argv);

	if (pid <= 0)
		return false;

	task->proc.pid = pid;
	task->proc.cb = mesh_task_done;
	uloop_process_add(&task->proc);
	task->busy = true;

	return true;
}

bool mesh_task_start(struct mesh_task *task, const char *script,
		     const char *arg1, const char *arg2)
{
	pid_t pid;

	if (task->busy)
		return false;

	pid = mesh_spawn(script, arg1, arg2);
	if (pid <= 0)
		return false;

	task->proc.pid = pid;
	task->proc.cb = mesh_task_done;
	uloop_process_add(&task->proc);
	task->busy = true;

	return true;
}

void mesh_task_stop(struct mesh_task *task)
{
	if (task->busy && task->proc.pid > 0)
		kill(-task->proc.pid, SIGTERM);
}

static void deps_done(struct mesh_task *task, int ret)
{
	deps_ready = ret == 0;

	if (!deps_ready)
		uloop_timeout_set(&deps_timer, MESH_DEPS_RETRY);
}

static void deps_cb(struct uloop_timeout *t)
{
	char *argv[3] = { MESH_DEPS_SCRIPT, "deps-ensure", NULL };

	if (deps_job.busy)
		return;

	if (!mesh_task_run(&deps_job, argv))
		uloop_timeout_set(&deps_timer, MESH_DEPS_RETRY);
}

void mesh_deps_start(void)
{
	if (deps_timer.cb)
		return;

	deps_timer.cb = deps_cb;
	uloop_timeout_set(&deps_timer, MESH_DEPS_FIRST);
}

void mesh_deps_blob(struct blob_buf *b)
{
	char *state = mesh_slurp(MESH_DEPS_STATE, 256);

	blobmsg_add_u8(b, "deps_ready", deps_ready);

	if (state) {
		state[strcspn(state, "\r\n")] = '\0';
		if (state[0])
			blobmsg_add_string(b, "deps_state", state);
		free(state);
	}
}

char *mesh_slurp(const char *path, size_t max)
{
	struct stat st;
	char *buf;
	int fd, n;
	size_t size = max;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (!fstat(fd, &st) && st.st_size >= 0 && (size_t)st.st_size < size)
		size = st.st_size;

	buf = malloc(size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}

	n = read(fd, buf, size);
	close(fd);
	if (n < 0) {
		free(buf);
		return NULL;
	}

	buf[n] = '\0';
	return buf;
}

struct mesh_config mesh;
struct list_head mesh_members = LIST_HEAD_INIT(mesh_members);

enum mesh_field_type {
	MESH_BOOL,
	MESH_ROLE,
	MESH_U32,
	MESH_INT,
	MESH_STR
};

struct mesh_field {
	const char *name;
	enum mesh_field_type type;
	size_t offset;
	size_t size;
};

#define MFIELD(n, t, f) { n, t, offsetof(struct mesh_config, f), sizeof(((struct mesh_config *)0)->f) }

static const struct mesh_field fields[] = {
	MFIELD("enabled", MESH_BOOL, enabled),
	MFIELD("role", MESH_ROLE, role),
	MFIELD("backhaul_enabled", MESH_BOOL, backhaul_enabled),
	MFIELD("backhaul_ssid", MESH_STR, backhaul_ssid),
	MFIELD("backhaul_key", MESH_STR, backhaul_key),
	MFIELD("backhaul_parents", MESH_STR, backhaul_parents),
	MFIELD("bh_limits", MESH_STR, bh_limits),
	MFIELD("ft_key", MESH_STR, ft_key),
	MFIELD("ft_kh", MESH_STR, ft_kh),
	MFIELD("ssh_pubkey", MESH_STR, ssh_pubkey[MESH_KEY_ED25519]),
	MFIELD("ssh_pubkey_rsa", MESH_STR, ssh_pubkey[MESH_KEY_RSA]),
	MFIELD("wifi_shutdown", MESH_BOOL, wifi_shutdown),
	MFIELD("node_ui", MESH_BOOL, node_ui),
	MFIELD("backhaul_delta", MESH_INT, backhaul_delta),
	MFIELD("backhaul_min_signal", MESH_INT, backhaul_min_signal),
	MFIELD("auto_update", MESH_BOOL, auto_update),
	MFIELD("auto_update_every", MESH_U32, auto_update_every),
	MFIELD("auto_update_unit", MESH_STR, auto_update_unit),
	MFIELD("auto_update_last", MESH_U32, auto_update_last),
	MFIELD("auto_update_result", MESH_STR, auto_update_result),
	MFIELD("pkg_url", MESH_STR, pkg_url),
	MFIELD("txpower_24", MESH_INT, txpower[BAND_LOW]),
	MFIELD("txpower_5", MESH_INT, txpower[BAND_HIGH]),
	MFIELD("channel_24", MESH_INT, channel[BAND_LOW]),
	MFIELD("channel_5", MESH_INT, channel[BAND_HIGH]),
	MFIELD("width_24", MESH_INT, width[BAND_LOW]),
	MFIELD("width_5", MESH_INT, width[BAND_HIGH]),
	MFIELD("country", MESH_STR, country),
	MFIELD("controller_id", MESH_STR, controller_id),
	MFIELD("controller_name", MESH_STR, controller_name),
	MFIELD("controller_addr", MESH_STR, controller_addr),
	MFIELD("controller_mac", MESH_STR, controller_mac),
	MFIELD("member_id", MESH_STR, member_id),
	MFIELD("networks_sum", MESH_STR, networks_sum)
};

#undef MFIELD

void mesh_unquote(char *s)
{
	size_t len = strlen(s);

	if (len >= 2 && (s[0] == '"' || s[0] == '\'') && s[len - 1] == s[0]) {
		memmove(s, s + 1, len - 2);
		s[len - 2] = 0;
	}
}

const char *mesh_role_name(enum mesh_role role)
{
	return role == MESH_NODE ? "node" : "controller";
}

const char *mesh_self_node_id(void)
{
	if (mesh.role == MESH_NODE && mesh.member_id[0])
		return mesh.member_id;

	return "controller";
}

void mesh_ft_nasid(const char *node, uint8_t band, char *out, size_t len)
{
	snprintf(out, len, "%s-%s", node, band == MESH_BAND_5 ? "5" : "2");
}

bool mesh_chain_has(const char *chain, const char *id)
{
	size_t len = strlen(id);
	const char *p = chain;

	while (len && (p = strstr(p, id))) {
		if ((p == chain || p[-1] == '-') && (p[len] == '\0' || p[len] == '-'))
			return true;

		p += len;
	}

	return false;
}

bool mesh_valid_id(const char *s)
{
	size_t i;

	if (!s || !s[0] || strlen(s) >= MESH_ID_MAX)
		return false;

	for (i = 0; s[i]; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_')
			return false;

	return true;
}

bool mesh_valid_task(const char *s)
{
	size_t i;

	if (!s || !s[0] || strlen(s) >= 32)
		return false;

	for (i = 0; s[i]; i++)
		if (!isdigit((unsigned char)s[i]))
			return false;

	return true;
}

bool mesh_valid_mac(const char *s)
{
	struct ether_addr ea;

	return s && strlen(s) == 17 && ether_aton_r(s, &ea);
}

const char *mesh_shq(char *out, size_t len, const char *s)
{
	size_t used = 0;

	if (!len)
		return "";

	for (; s && *s; s++) {
		const char *piece = *s == '\'' ? "'\\''" : NULL;
		size_t n = piece ? 4 : 1;

		if (used + n >= len) {
			used = 0;
			break;
		}

		if (piece)
			memcpy(out + used, piece, n);
		else
			out[used] = *s;

		used += n;
	}

	out[used] = 0;

	return out;
}

bool mesh_valid_hex(const char *s)
{
	size_t i, len = s ? strlen(s) : 0;

	if (!len || len % 2)
		return false;

	for (i = 0; i < len; i++)
		if (!isxdigit((unsigned char)s[i]))
			return false;

	return true;
}

bool mesh_valid_addr(const char *s)
{
	char host[MESH_ADDR_MAX];
	unsigned char buf[sizeof(struct in6_addr)];
	const char *zone;
	size_t i;

	if (!s || !s[0] || strlen(s) >= sizeof(host))
		return false;

	snprintf(host, sizeof(host), "%s", s);
	zone = strchr(host, '%');
	if (zone) {
		host[zone - host] = 0;
		zone = s + (zone - host) + 1;

		if (!zone[0] || strlen(zone) >= IFNAMSIZ)
			return false;

		for (i = 0; zone[i]; i++)
			if (!isalnum((unsigned char)zone[i]) && !strchr("-_.", zone[i]))
				return false;

		return inet_pton(AF_INET6, host, buf) == 1;
	}

	return inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1;
}

uint8_t mesh_band_bit(const char *name)
{
	if (!name || !name[0])
		return 0;

	return name[0] == '2' ? MESH_BAND_24 : MESH_BAND_5;
}

enum roam_band mesh_band_from_bit(uint8_t bit)
{
	return bit == MESH_BAND_5 ? BAND_HIGH : BAND_LOW;
}

static uint8_t local_band_mask(void)
{
	struct roam_bss *bss;
	uint8_t mask = 0;

	list_for_each_entry(bss, &roam_bss_list, list)
		if (roam_bss_matches(bss))
			mask |= roam_band_bit(bss->band);

	return mask;
}

bool mesh_band_usable(uint8_t bit)
{
	if (!bit)
		return true;

	if (mesh.role == MESH_NODE && mesh.enabled)
		return local_band_mask() & bit;

	return (mesh.band_mask | local_band_mask()) & bit;
}

static const char *bss_nr_hex(struct blob_attr *nr)
{
	struct blob_attr *cur;
	const char *best = NULL;
	size_t best_len = 0;
	int rem;

	if (!nr)
		return NULL;

	blobmsg_for_each_attr(cur, nr, rem) {
		if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
			const char *s = blobmsg_get_string(cur);
			size_t len = strlen(s);

			if (len > best_len) {
				best_len = len;
				best = s;
			}
		}
	}

	return best;
}

void mesh_aps_dump(struct blob_buf *b, const char *name)
{
	struct roam_bss *bss;
	void *arr = blobmsg_open_array(b, name);

	list_for_each_entry(bss, &roam_bss_list, list) {
		const char *nr;
		char bssid[18];
		void *e;

		if (!bss->ssid[0])
			continue;

		nr = bss_nr_hex(bss->nr);
		e = blobmsg_open_table(b, NULL);

		roam_mac_str(bss->bssid, bssid, sizeof(bssid));

		blobmsg_add_string(b, "ifname", bss->ifname);
		blobmsg_add_string(b, "bssid", bssid);
		blobmsg_add_string(b, "ssid", bss->ssid);
		blobmsg_add_u32(b, "channel", bss->channel);
		blobmsg_add_string(b, "band", roam_band_name(bss->band));
		blobmsg_add_u8(b, "neighbor_report", !!bss->nr);
		if (nr)
			blobmsg_add_string(b, "nr", nr);
		blobmsg_close_table(b, e);
	}

	blobmsg_close_array(b, arr);
}

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
	uint32_t id;

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

	if (changed && !ubus_lookup_id(ubus_ctx, "network", &id))
		ubus_invoke(ubus_ctx, id, "reload", NULL, NULL, NULL, 1000);
}

struct mesh_neighbor {
	char bssid[18];
	char ssid[MESH_SSID_MAX];
	char nr[160];
};

static struct mesh_neighbor mesh_nbr[MESH_NBR_MAX];
static unsigned int mesh_nbr_n;

static bool nr_valid(const char *nr)
{
	return mesh_valid_hex(nr) && strlen(nr) < sizeof(((struct mesh_neighbor *)0)->nr);
}

void mesh_neighbors_set(struct blob_attr *arr)
{
	enum { N_BSSID, N_SSID, N_NR, __N_MAX };
	static const struct blobmsg_policy np[__N_MAX] = {
		[N_BSSID] = { "bssid", BLOBMSG_TYPE_STRING },
		[N_SSID] = { "ssid", BLOBMSG_TYPE_STRING },
		[N_NR] = { "nr", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *cur;
	int rem;

	mesh_nbr_n = 0;
	if (!arr)
		return;

	blobmsg_for_each_attr(cur, arr, rem) {
		struct blob_attr *tb[__N_MAX];
		struct mesh_neighbor *n;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE || mesh_nbr_n >= MESH_NBR_MAX)
			continue;

		blobmsg_parse(np, __N_MAX, tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[N_BSSID] || !tb[N_NR] ||
		    !mesh_valid_mac(blobmsg_get_string(tb[N_BSSID])) ||
		    !nr_valid(blobmsg_get_string(tb[N_NR])))
			continue;

		n = &mesh_nbr[mesh_nbr_n++];
		memset(n, 0, sizeof(*n));
		strncpy(n->bssid, blobmsg_get_string(tb[N_BSSID]), sizeof(n->bssid) - 1);
		if (tb[N_SSID])
			strncpy(n->ssid, blobmsg_get_string(tb[N_SSID]), sizeof(n->ssid) - 1);
		strncpy(n->nr, blobmsg_get_string(tb[N_NR]), sizeof(n->nr) - 1);
	}
}

static bool nbr_is_local(const char *bssid)
{
	struct roam_bss *bss;

	list_for_each_entry(bss, &roam_bss_list, list) {
		char bs[18];

		roam_mac_str(bss->bssid, bs, sizeof(bs));
		if (!strcasecmp(bs, bssid))
			return true;
	}

	return false;
}

void mesh_neighbors_append(struct blob_buf *b, const char *ssid, int *count, int max)
{
	unsigned int i;

	for (i = 0; i < mesh_nbr_n && *count < max; i++) {
		struct mesh_neighbor *n = &mesh_nbr[i];
		void *e;

		if (ssid && n->ssid[0] && strcmp(n->ssid, ssid))
			continue;
		if (nbr_is_local(n->bssid))
			continue;

		e = blobmsg_open_array(b, NULL);
		blobmsg_add_string(b, NULL, n->bssid);
		blobmsg_add_string(b, NULL, n->ssid);
		blobmsg_add_string(b, NULL, n->nr);
		blobmsg_close_array(b, e);
		(*count)++;
	}
}

#define MESH_PEER_STA_MAX	256
#define MESH_PEER_STA_TTL	60000

static uint8_t peer_sta[MESH_PEER_STA_MAX][6];
static unsigned int peer_sta_n;
static uint64_t peer_sta_at;

void mesh_peer_clients_set(struct blob_attr *arr)
{
	struct blob_attr *cur;
	int rem;

	peer_sta_n = 0;
	if (!arr)
		return;

	roam_time_update();
	peer_sta_at = roam_now;

	blobmsg_for_each_attr(cur, arr, rem) {
		struct ether_addr ea;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || peer_sta_n >= MESH_PEER_STA_MAX)
			continue;

		if (!ether_aton_r(blobmsg_get_string(cur), &ea))
			continue;

		memcpy(peer_sta[peer_sta_n++], ea.ether_addr_octet, 6);
	}
}

bool mesh_peer_client(const uint8_t *addr)
{
	unsigned int i;

	if (!peer_sta_n || roam_now - peer_sta_at > MESH_PEER_STA_TTL)
		return false;

	for (i = 0; i < peer_sta_n; i++)
		if (!memcmp(peer_sta[i], addr, 6))
			return true;

	return false;
}

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
	enum { A_MAC, A_RX, A_TX, A_CONNECTED, __A_MAX };
	static const struct blobmsg_policy ap[__A_MAX] = {
		[A_MAC] = { "mac", BLOBMSG_TYPE_STRING },
		[A_RX] = { "rx", BLOBMSG_TYPE_TABLE },
		[A_TX] = { "tx", BLOBMSG_TYPE_TABLE },
		[A_CONNECTED] = { "connected_time", BLOBMSG_TYPE_INT32 },
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
		if (ctx->enc)
			strncpy(a->enc, ctx->enc, sizeof(a->enc) - 1);
		if (tb[A_TX])
			assoc_phy(tb[A_TX], a);
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

static void assoc_refine_enc(struct roam_bss *bss, struct mesh_assoc *a)
{
	static struct blob_buf sb;
	char mac[18];

	if (!bss->obj_id)
		return;

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 a->addr[0], a->addr[1], a->addr[2], a->addr[3], a->addr[4], a->addr[5]);

	blob_buf_init(&sb, 0);
	blobmsg_add_string(&sb, "address", mac);
	ubus_invoke(ubus_ctx, bss->obj_id, "get_sta_ies", sb.head, sta_ies_cb, a, MESH_UBUS_TIMEOUT);
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
	if (a->wired) {
		blobmsg_add_u8(b, "wired", 1);
		return;
	}

	if (a->rate)
		blobmsg_add_u32(b, "rate", a->rate);
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

void mesh_members_clear(void)
{
	struct mesh_member *m, *tmp;

	list_for_each_entry_safe(m, tmp, &mesh_members, list) {
		list_del(&m->list);
		free(m);
	}
}

struct mesh_member *mesh_member_by_name(const char *name)
{
	struct mesh_member *m;

	list_for_each_entry(m, &mesh_members, list)
		if (!strcmp(m->name, name))
			return m;

	return NULL;
}

void mesh_config_init(void)
{
	memset(&mesh, 0, sizeof(mesh));

	mesh.enabled = true;
	mesh.role = MESH_CONTROLLER;
	mesh.backhaul_enabled = true;
	mesh.backhaul_delta = MESH_BH_DELTA_DEFAULT;
	mesh.backhaul_min_signal = MESH_BH_MIN_SIGNAL_DEFAULT;
	mesh.auto_update_every = 1;
	strcpy(mesh.auto_update_unit, "day");
	strcpy(mesh.pkg_url, MESH_PKG_URL_DEFAULT);

	mesh_members_clear();
}

static void member_str(struct uci_context *ctx, struct uci_section *s,
		       const char *name, char *dst, size_t size)
{
	const char *v = uci_lookup_option_string(ctx, s, name);

	if (v) {
		strncpy(dst, v, size - 1);
		dst[size - 1] = '\0';
	}
}

void mesh_member_load(struct uci_context *ctx, struct uci_section *s)
{
	const char *managed = uci_lookup_option_string(ctx, s, "managed");
	struct mesh_member *m = calloc(1, sizeof(*m));

	if (!m)
		return;

	member_str(ctx, s, "id", m->id, sizeof(m->id));
	member_str(ctx, s, "name", m->name, sizeof(m->name));
	member_str(ctx, s, "hostname", m->hostname, sizeof(m->hostname));
	member_str(ctx, s, "mac", m->mac, sizeof(m->mac));
	member_str(ctx, s, "addr", m->addr, sizeof(m->addr));
	m->managed = managed ? roam_uci_bool(managed) : true;

	{
		unsigned int k;

		for (k = 0; k < __MESH_RADIO_MAX; k++) {
			const char *v = uci_lookup_option_string(ctx, s, mesh_radio_opts[k]);

			*mesh_radio_slot(m->txpower, m->channel, m->width, k) = v ? atoi(v) : 0;
		}
	}

	{
		struct uci_option *o = uci_lookup_option(ctx, s, "bh_node");
		struct uci_element *e;
		size_t used = 0;

		if (o && o->type == UCI_TYPE_LIST)
			uci_foreach_element(&o->v.list, e) {
				int n = snprintf(m->bh_nodes + used, sizeof(m->bh_nodes) - used,
						 "%s%s", used ? "-" : "", e->name);

				if (n < 0 || (size_t)n >= sizeof(m->bh_nodes) - used)
					break;

				used += (size_t)n;
			}
	}

	list_add_tail(&m->list, &mesh_members);
}

static void field_apply(const struct mesh_field *f, const char *value)
{
	void *p = (char *)&mesh + f->offset;

	switch (f->type) {
	case MESH_BOOL:
		*(bool *)p = roam_uci_bool(value);
		break;
	case MESH_ROLE:
		*(enum mesh_role *)p = strcmp(value, "node") ? MESH_CONTROLLER : MESH_NODE;
		break;
	case MESH_U32:
		*(uint32_t *)p = strtoul(value, NULL, 10);
		break;
	case MESH_INT:
		*(int *)p = strtol(value, NULL, 10);
		break;
	case MESH_STR:
		strncpy(p, value, f->size - 1);
		((char *)p)[f->size - 1] = '\0';
		break;
	}
}

void mesh_config_apply(struct uci_context *ctx, struct uci_section *s)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		const char *v = uci_lookup_option_string(ctx, s, fields[i].name);

		if (v)
			field_apply(&fields[i], v);
	}

	if (!mesh.pkg_url[0])
		snprintf(mesh.pkg_url, sizeof(mesh.pkg_url), "%s", MESH_PKG_URL_DEFAULT);
}

static struct uloop_timeout ft_watch;
static struct mesh_task wpad_job;
static bool ft_restarted;

static bool rrb_orphaned(void)
{
	char line[256];
	FILE *f = fopen("/proc/net/packet", "r");
	bool found = false, bound = false;

	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		char sk[32], proto[16];
		unsigned int refcnt, type;
		int iface;

		if (sscanf(line, "%31s %u %u %15s %d", sk, &refcnt, &type, proto, &iface) != 5)
			continue;

		if (strcmp(proto, MESH_RRB_PROTO))
			continue;

		found = true;
		if (iface > 0)
			bound = true;
	}

	fclose(f);

	return found && !bound;
}

static void ft_watch_cb(struct uloop_timeout *t)
{
	mesh_node_key_ensure();

	if (!config.fast_transition || !rrb_orphaned())
		ft_restarted = false;
	else if (!ft_restarted) {
		ft_restarted = true;
		roam_log(ROAM_L_INFO,
			 "mesh: key exchange socket lost its bridge, restarting wpad");
		mesh_task_start(&wpad_job, MESH_RC_COMMON, MESH_WPAD_INIT, "restart");
	}

	uloop_timeout_set(t, MESH_FT_WATCH_INTERVAL);
}

void mesh_start(void)
{
	static bool log_loaded;

	if (!mesh.enabled) {
		roam_log(ROAM_L_INFO, "mesh: disabled");
		return;
	}

	if (!log_loaded) {
		mesh_log_load();
		mesh_clients_load();
		log_loaded = true;
	}

	mesh_deps_start();

	ft_watch.cb = ft_watch_cb;
	uloop_timeout_set(&ft_watch, MESH_FT_WATCH_INTERVAL);

	if (mesh.role == MESH_NODE) {
		roam_log(ROAM_L_INFO, "mesh: node of controller %s (%s)",
			 mesh.controller_id[0] ? mesh.controller_id : "?",
			 mesh.controller_addr[0] ? mesh.controller_addr : "?");
		mesh_node_watch_start();
		mesh_node_dumbap();
	} else {
		mesh_ctrl_ensure_id();
		mesh_ssh_key_ensure();
		roam_log(ROAM_L_INFO, "mesh: controller %s", mesh.controller_id);
		mesh_ctrl_backhaul_apply();
		mesh_ctrl_txpower_apply();
		mesh_ctrl_radio_apply(false);
		mesh_ctrl_bridge_stp();
		mesh_ctrl_poll_start();
		mesh_ctrl_autoupdate_arm();
		mesh_ctrl_sync();
	}
}
