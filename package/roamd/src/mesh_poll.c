#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>

#include <netinet/ether.h>

#include <libubox/blobmsg_json.h>

#include "roamd.h"
#include "mesh.h"

#define MEMBERS_DIR	"/var/run/roamd/members"
#define POLL_STA_MAX	32
#define POLL_AP_MAX	8
#define POLL_NODE_MAX	(MESH_ALLOW_MAX + 1)
#define POLL_NR_MAX	160
#define SELF_ID		"controller"
#define POLL_WATCHDOG_TIMEOUT	29000
#define POLL_MISS_LIMIT	2
#define KH_BSSID_NONE		"00:00:00:00:00:00|"

#define POLL_MEAS_MAX	8

struct poll_meas {
	char bssid[MESH_MAC_MAX];
	int signal;
};

struct poll_sta {
	uint8_t addr[6];
	char mac[MESH_MAC_MAX];
	char ssid[MESH_SSID_MAX];
	int signal;
	uint32_t connected;
	uint8_t band;
	bool client;
	bool has_btm;
	bool btm_paused;
	int btm_status;
	uint32_t btm_age;
	struct poll_meas meas[POLL_MEAS_MAX];
	unsigned int n_meas;
};

struct poll_ap {
	char bssid[MESH_MAC_MAX];
	char ssid[MESH_SSID_MAX];
	char band[4];
	char nr[POLL_NR_MAX];
};

struct poll_node {
	char id[MESH_ID_MAX];
	char addr[MESH_ADDR_MAX];
	char name[MESH_NAME_MAX];
	bool managed;
	bool online;
	bool answered;
	unsigned int misses;
	struct poll_sta sta[POLL_STA_MAX];
	unsigned int n_sta;
	struct poll_ap ap[POLL_AP_MAX];
	unsigned int n_ap;
};

struct poll_call {
	unsigned int gen;
	struct poll_node *node;
};

struct sta_ref {
	uint8_t node;
	uint8_t sta;
};

static struct poll_node nodes[POLL_NODE_MAX];
static unsigned int n_nodes;
static struct sta_ref refs[POLL_NODE_MAX * POLL_STA_MAX];
static unsigned int n_refs;
static unsigned int waiting;
static unsigned int poll_gen;
static bool busy;
static bool force_pending;
static bool force_apply;
static char *profile_json;
static char poll_radio[64];

static void radio_sig(char *out, size_t len)
{
	snprintf(out, len, "%s/%d/%d/%d/%d", mesh.country, mesh.channel[BAND_LOW],
		 mesh.channel[BAND_HIGH], mesh.width[BAND_LOW], mesh.width[BAND_HIGH]);
}
static char profile_sum[MESH_NET_SUM_LEN];
static void poll_watchdog_cb(struct uloop_timeout *t);
static void cardinal_push(void);
static struct uloop_timeout poll_watchdog = { .cb = poll_watchdog_cb };

bool mesh_poll_busy(void)
{
	return busy;
}

bool mesh_poll_has_place(const uint8_t *addr)
{
	unsigned int i, j;

	if (!n_nodes)
		return true;

	for (i = 0; i < n_nodes; i++) {
		const struct poll_node *n = &nodes[i];

		if (!n->online)
			continue;

		for (j = 0; j < n->n_ap; j++) {
			uint8_t bit = mesh_band_bit(n->ap[j].band);

			if (mesh.backhaul_ssid[0] && !strcmp(n->ap[j].ssid, mesh.backhaul_ssid))
				continue;

			if (roam_admit(addr, n->id, mesh_band_from_bit(bit)) == ADMIT_OK)
				return true;
		}
	}

	return false;
}

static const char *attr_str(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return NULL;

	blobmsg_for_each_attr(cur, table, rem) {
		if (strcmp(blobmsg_name(cur), name))
			continue;

		if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
			return blobmsg_get_string(cur);

		if (blobmsg_type(cur) == BLOBMSG_TYPE_BOOL)
			return blobmsg_get_bool(cur) ? "true" : "false";

		return NULL;
	}

	return NULL;
}

static struct blob_attr *attr_field(struct blob_attr *table, const char *name, int type)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return NULL;

	blobmsg_for_each_attr(cur, table, rem)
		if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == type)
			return cur;

	return NULL;
}

static struct blob_attr *root_field(struct blob_buf *b, const char *name, int type)
{
	struct blob_attr *cur;
	int rem;

	blob_for_each_attr(cur, b->head, rem)
		if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == type)
			return cur;

	return NULL;
}

static uint32_t attr_u32(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur = attr_field(table, name, BLOBMSG_TYPE_INT32);

	return cur ? blobmsg_get_u32(cur) : 0;
}

static void meas_collect(struct poll_sta *s, struct blob_attr *list)
{
	struct blob_attr *cur;
	int rem;

	if (!list)
		return;

	blobmsg_for_each_attr(cur, list, rem) {
		struct poll_meas *m;
		const char *bssid;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE || s->n_meas >= POLL_MEAS_MAX)
			continue;

		bssid = attr_str(cur, "bssid");
		if (!bssid || !mesh_valid_mac(bssid) || !attr_field(cur, "signal", BLOBMSG_TYPE_INT32))
			continue;

		if ((uint64_t)attr_u32(cur, "age") * 1000 > roam_meas_fresh())
			continue;

		m = &s->meas[s->n_meas++];
		snprintf(m->bssid, sizeof(m->bssid), "%s", bssid);
		m->signal = (int)attr_u32(cur, "signal");
	}
}

static void sta_collect(struct poll_node *n, struct blob_attr *list, bool client)
{
	struct blob_attr *cur;
	int rem;

	if (!list)
		return;

	blobmsg_for_each_attr(cur, list, rem) {
		struct poll_sta *s;
		struct ether_addr *ea;
		const char *mac, *ssid;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE || n->n_sta >= POLL_STA_MAX)
			continue;

		mac = attr_str(cur, "mac");
		if (!mac || !mesh_valid_mac(mac) || !attr_field(cur, "signal", BLOBMSG_TYPE_INT32))
			continue;

		ea = ether_aton(mac);
		if (!ea)
			continue;

		s = &n->sta[n->n_sta++];
		memset(s, 0, sizeof(*s));
		memcpy(s->addr, ea->ether_addr_octet, sizeof(s->addr));
		snprintf(s->mac, sizeof(s->mac), "%s", mac);
		ssid = attr_str(cur, "ssid");
		if (ssid)
			snprintf(s->ssid, sizeof(s->ssid), "%s", ssid);
		s->signal = (int)attr_u32(cur, "signal");
		s->connected = client ? attr_u32(cur, "connected") : 0;
		s->band = mesh_band_bit(attr_str(cur, "band"));
		s->client = client;

		if (client && attr_field(cur, "btm_status", BLOBMSG_TYPE_INT32)) {
			s->has_btm = true;
			s->btm_status = (int)attr_u32(cur, "btm_status");
			s->btm_age = attr_u32(cur, "btm_age");
		}
		s->btm_paused = client && attr_field(cur, "btm_paused", BLOBMSG_TYPE_BOOL);
		if (client)
			meas_collect(s, attr_field(cur, "reports", BLOBMSG_TYPE_ARRAY));
	}
}

static void ap_collect(struct poll_node *n, struct blob_attr *list)
{
	struct blob_attr *cur;
	int rem;

	if (!list)
		return;

	blobmsg_for_each_attr(cur, list, rem) {
		struct poll_ap *a;
		const char *bssid, *ssid, *band, *nr;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE || n->n_ap >= POLL_AP_MAX)
			continue;

		bssid = attr_str(cur, "bssid");
		ssid = attr_str(cur, "ssid");
		if (!bssid || !ssid || !mesh_valid_mac(bssid))
			continue;

		a = &n->ap[n->n_ap++];
		memset(a, 0, sizeof(*a));
		snprintf(a->bssid, sizeof(a->bssid), "%s", bssid);
		snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
		band = attr_str(cur, "band");
		if (band)
			snprintf(a->band, sizeof(a->band), "%s", band);
		nr = attr_str(cur, "nr");
		if (nr && mesh_valid_hex(nr) && strlen(nr) < sizeof(a->nr))
			snprintf(a->nr, sizeof(a->nr), "%s", nr);
	}
}

static bool member_field_reserved(const char *name)
{
	static const char *const reserved[] = {
		"online", "update_available", "consistency", "pkg_source", "issues",
		"id", "managed", "bh_nodes", "bh_nodes_void", "hostname"
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(reserved); i++)
		if (!strcmp(name, reserved[i]))
			return true;

	return false;
}

static void member_file_write(const struct poll_node *n, struct blob_attr *report,
			      const char *consistency, const char *issues, bool update)
{
	char path[128], tmp[136], *json;
	struct blob_buf b = { 0 };
	struct blob_attr *cur;
	char *src;
	int rem;
	FILE *f;

	snprintf(path, sizeof(path), MEMBERS_DIR "/%s.json", n->id);
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	blob_buf_init(&b, 0);

	if (report)
		blobmsg_for_each_attr(cur, report, rem)
			if (!member_field_reserved(blobmsg_name(cur)))
				blobmsg_add_blob(&b, cur);

	blobmsg_add_u8(&b, "online", report != NULL);

	if (report) {
		char spath[128];

		blobmsg_add_u8(&b, "update_available", update);
		blobmsg_add_string(&b, "consistency", consistency);

		snprintf(spath, sizeof(spath), MEMBERS_DIR "/%s.pkgsrc", n->id);
		src = mesh_slurp(spath, 32);
		if (src) {
			src[strcspn(src, "\r\n")] = 0;
			blobmsg_add_string(&b, "pkg_source", src);
			free(src);
		}

		{
			void *arr = blobmsg_open_array(&b, "issues");

			if (issues && issues[0])
				blobmsg_add_string(&b, NULL, issues);

			blobmsg_close_array(&b, arr);
		}
	}

	json = blobmsg_format_json(b.head, true);
	blob_buf_free(&b);

	if (!json)
		return;

	f = fopen(tmp, "w");
	if (f) {
		bool ok = fputs(json, f) >= 0;

		ok = !fclose(f) && ok;
		if (ok)
			rename(tmp, path);
		else
			unlink(tmp);
	}

	free(json);
}

static bool member_update_available(struct blob_attr *report)
{
	const char *os = attr_str(report, "os_version");
	const char *arch = attr_str(report, "arch");
	const char *have = attr_str(report, "pkg_version");
	const char *have_ui = attr_str(report, "ui_version");
	struct mesh_pkg_meta meta;
	char branch[MESH_WORD_MAX];
	const char *dot;

	if (!os || !arch || !have)
		return false;

	dot = strrchr(os, '.');
	snprintf(branch, sizeof(branch), "%.*s", dot ? (int)(dot - os) : (int)strlen(os), os);

	if (mesh_pkg_stale(branch, arch, MESH_PKG_MAIN))
		mesh_pkg_refresh(branch, arch, MESH_PKG_MAIN, NULL, NULL);

	if (mesh_pkg_known(branch, arch, MESH_PKG_MAIN, &meta) &&
	    mesh_pkg_newer(have, meta.version) > 0)
		return true;

	if (!have_ui)
		return false;

	if (mesh_pkg_stale(branch, arch, MESH_PKG_UI))
		mesh_pkg_refresh(branch, arch, MESH_PKG_UI, NULL, NULL);

	return mesh_pkg_known(branch, arch, MESH_PKG_UI, &meta) &&
	       mesh_pkg_newer(have_ui, meta.version) > 0;
}

static void steer_round(void);

static void bands_refresh(void)
{
	uint8_t mask = 0;
	unsigned int i, j;

	for (i = 0; i < n_nodes; i++)
		for (j = 0; j < nodes[i].n_ap; j++) {
			const struct poll_ap *a = &nodes[i].ap[j];

			if (mesh.backhaul_ssid[0] && !strcmp(a->ssid, mesh.backhaul_ssid))
				continue;

			mask |= mesh_band_bit(a->band);
		}

	mesh.band_mask = mask;
}

static int kh_cmp(const void *a, const void *b)
{
	return strcmp(a, b);
}

static bool kh_owner_member(const char *nasid)
{
	const char *dash = strrchr(nasid, '-');
	size_t len = dash ? (size_t)(dash - nasid) : strlen(nasid);
	struct mesh_member *m;

	if (!strncmp(nasid, SELF_ID, len) && !SELF_ID[len])
		return true;

	list_for_each_entry(m, &mesh_members, list)
		if (!strncmp(m->id, nasid, len) && !m->id[len])
			return true;

	return false;
}

static bool kh_bssid_listed(char entries[][MESH_MAC_MAX + MESH_NASID_MAX + 2],
			    unsigned int count, const char *tok)
{
	size_t len = strcspn(tok, "|");
	unsigned int i;

	for (i = 0; i < count; i++)
		if (!strncasecmp(entries[i], tok, len) && entries[i][len] == '|')
			return true;

	return false;
}

static void ft_kh_refresh(void)
{
	char entries[MESH_FT_KH_MAX][MESH_MAC_MAX + MESH_NASID_MAX + 2];
	char list[MESH_FT_KH_LEN], kept[MESH_FT_KH_LEN];
	struct uci_session u;
	unsigned int count = 0, i, j;
	char *tok, *save = NULL;
	size_t used = 0;

	for (i = 0; i < n_nodes; i++) {
		const struct poll_node *n = &nodes[i];

		if (!n->online)
			continue;

		for (j = 0; j < n->n_ap && count < MESH_FT_KH_MAX; j++) {
			const struct poll_ap *a = &n->ap[j];
			char nasid[MESH_NASID_MAX];
			uint8_t bit = mesh_band_bit(a->band);

			if (!a->bssid[0] || !bit)
				continue;

			if (mesh.backhaul_ssid[0] && !strcmp(a->ssid, mesh.backhaul_ssid))
				continue;

			mesh_ft_nasid(n->id, bit, nasid, sizeof(nasid));
			snprintf(entries[count++], sizeof(entries[0]), "%s|%s", a->bssid, nasid);
		}
	}

	snprintf(kept, sizeof(kept), "%s", mesh.ft_kh);

	for (tok = strtok_r(kept, " ", &save); tok && count < MESH_FT_KH_MAX;
	     tok = strtok_r(NULL, " ", &save)) {
		const char *nasid = strchr(tok, '|');

		if (!nasid || !strncmp(tok, KH_BSSID_NONE, strlen(KH_BSSID_NONE)) ||
		    !kh_owner_member(nasid + 1) || kh_bssid_listed(entries, count, tok))
			continue;

		snprintf(entries[count++], sizeof(entries[0]), "%s", tok);
	}

	qsort(entries, count, sizeof(entries[0]), kh_cmp);

	list[0] = '\0';

	for (i = 0; i < count; i++) {
		int len = snprintf(list + used, sizeof(list) - used, "%s%s",
				   used ? " " : "", entries[i]);

		if (len < 0 || (size_t)len >= sizeof(list) - used)
			break;

		used += len;
	}

	if (!strcmp(mesh.ft_kh, list))
		return;

	snprintf(mesh.ft_kh, sizeof(mesh.ft_kh), "%s", list);

	if (uci_session_open(&u, "roamd")) {
		uci_session_add(&u, "mesh", "mesh");
		uci_session_set(&u, "mesh", "ft_kh", list);
		uci_session_close(&u);
	}

	roam_wireless_apply();
}

static void poll_finish(void)
{
	if (--waiting)
		return;

	uloop_timeout_cancel(&poll_watchdog);
	bands_refresh();
	ft_kh_refresh();
	steer_round();
	cardinal_push();
	{
		char now[sizeof(poll_radio)];

		radio_sig(now, sizeof(now));
		if (!strcmp(poll_radio, now))
			mesh_ctrl_radio_apply(true);
	}
	busy = false;
}

static void node_missed(struct poll_node *n)
{
	if (++n->misses >= POLL_MISS_LIMIT)
		member_file_write(n, NULL, NULL, NULL, false);
}

static void poll_watchdog_cb(struct uloop_timeout *t)
{
	unsigned int i;

	roam_log(ROAM_L_ERR, "mesh: %u nodes did not answer in %d s, marked offline",
		 waiting, POLL_WATCHDOG_TIMEOUT / 1000);

	poll_gen++;

	for (i = 1; i < n_nodes; i++)
		if (!nodes[i].answered)
			node_missed(&nodes[i]);

	waiting = 1;
	poll_finish();
}

static void node_report(struct poll_node *n, struct blob_attr *result)
{
	struct blob_attr *profile;
	const char *nets, *bh;
	const char *issue = NULL;
	const char *cons = "ok";

	n->answered = true;

	if (!result) {
		node_missed(n);
		poll_finish();

		return;
	}

	n->misses = 0;
	n->online = true;
	mesh_member_hostname(n->id, attr_str(result, "hostname"));
	sta_collect(n, attr_field(result, "clients", BLOBMSG_TYPE_ARRAY), true);
	sta_collect(n, attr_field(result, "heard", BLOBMSG_TYPE_ARRAY), false);
	ap_collect(n, attr_field(result, "aps", BLOBMSG_TYPE_ARRAY));

	profile = attr_field(result, "profile", BLOBMSG_TYPE_TABLE);
	nets = attr_str(profile, "networks_sum");
	bh = attr_str(profile, "backhaul_ssid");

	if (profile_sum[0] && (!nets || strcmp(nets, profile_sum))) {
		issue = "networks";
		cons = "broken";
	} else if (mesh.backhaul_ssid[0] && (!bh || strcmp(bh, mesh.backhaul_ssid))) {
		issue = "backhaul";
		cons = "degraded";
	}

	member_file_write(n, result, cons, issue, member_update_available(result));

	{
		struct blob_attr *events = attr_field(result, "events", BLOBMSG_TYPE_ARRAY);

		if (events && n->name[0])
			mesh_log_ingest(n->id, n->name, events);
	}

	poll_finish();
}

static struct poll_node *call_node(const struct poll_call *c)
{
	return c->gen == poll_gen ? c->node : NULL;
}

static void report_cb(void *priv, struct blob_attr *result, bool ok)
{
	struct poll_call *c = priv;
	struct poll_node *n = call_node(c);

	free(c);

	if (n)
		node_report(n, ok ? result : NULL);
}

static void apply_cb(void *priv, struct blob_attr *result, bool ok)
{
	struct poll_call *c = priv;
	struct poll_node *n = call_node(c);

	if (!n) {
		free(c);
		return;
	}

	if (!mesh_rpc_call(n->id, n->addr, "roamd", "mesh_report", NULL, report_cb, c))
		report_cb(c, NULL, false);
}

static void self_collect(void)
{
	static struct blob_buf self;
	struct poll_node *n = &nodes[0];

	memset(n, 0, sizeof(*n));
	snprintf(n->id, sizeof(n->id), SELF_ID);
	snprintf(n->addr, sizeof(n->addr), "local");
	n->online = true;

	blob_buf_init(&self, 0);
	mesh_node_report(&self);

	sta_collect(n, root_field(&self, "clients", BLOBMSG_TYPE_ARRAY), true);
	sta_collect(n, root_field(&self, "heard", BLOBMSG_TYPE_ARRAY), false);
	ap_collect(n, root_field(&self, "aps", BLOBMSG_TYPE_ARRAY));
}

static bool profile_build(void)
{
	static struct blob_buf b;
	char *json;
	const char *sum;
	bool changed;

	blob_buf_init(&b, 0);
	mesh_profile_build(&b);

	sum = mesh_networks_sum();
	snprintf(profile_sum, sizeof(profile_sum), "%s", sum ? sum : "");

	json = blobmsg_format_json(b.head, true);
	if (!json)
		return false;

	changed = !profile_json || strcmp(profile_json, json);
	free(profile_json);
	profile_json = json;

	return changed;
}

static unsigned int misses_of(const char *id, char ids[][MESH_ID_MAX],
			      const unsigned int *counts, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		if (!strcmp(ids[i], id))
			return counts[i];

	return 0;
}

void mesh_poll_run(bool force)
{
	char prev_ids[POLL_NODE_MAX][MESH_ID_MAX];
	unsigned int prev_misses[POLL_NODE_MAX], n_prev, i;
	struct mesh_member *m;

	if (mesh.role != MESH_CONTROLLER || list_empty(&mesh_members))
		return;

	if (busy) {
		force_pending = force_pending || force;

		return;
	}

	force = force || force_pending;
	force_pending = false;

	mesh_dir_ensure(MEMBERS_DIR);

	if (profile_build())
		force = true;

	radio_sig(poll_radio, sizeof(poll_radio));
	force_apply = force;

	for (i = 0; i < n_nodes; i++) {
		memcpy(prev_ids[i], nodes[i].id, sizeof(prev_ids[i]));
		prev_misses[i] = nodes[i].misses;
	}
	n_prev = n_nodes;

	self_collect();
	n_nodes = 1;
	waiting = 1;
	busy = true;
	uloop_timeout_set(&poll_watchdog, POLL_WATCHDOG_TIMEOUT);

	list_for_each_entry(m, &mesh_members, list) {
		struct poll_node *n;
		struct poll_call *c;
		char state[MESH_WORD_MAX];
		bool was_online, was_ok, apply;

		if (n_nodes >= POLL_NODE_MAX || !m->id[0] || !m->addr[0])
			continue;

		n = &nodes[n_nodes++];
		memset(n, 0, sizeof(*n));
		snprintf(n->id, sizeof(n->id), "%s", m->id);
		snprintf(n->addr, sizeof(n->addr), "%s", m->addr);
		snprintf(n->name, sizeof(n->name), "%s", m->name);
		n->managed = m->managed;
		n->misses = misses_of(m->id, prev_ids, prev_misses, n_prev);

		was_online = mesh_member_state(m->id, "online", state, sizeof(state)) &&
			     !strcmp(state, "true");
		was_ok = mesh_member_state(m->id, "consistency", state, sizeof(state)) &&
			 !strcmp(state, "ok");
		apply = n->managed && (force_apply || !was_online || !was_ok);

		waiting++;

		c = malloc(sizeof(*c));
		if (!c) {
			node_report(n, NULL);
			continue;
		}

		c->gen = poll_gen;
		c->node = n;

		if (apply && profile_json &&
		    mesh_rpc_call(n->id, n->addr, "roamd", "mesh_apply", profile_json, apply_cb, c))
			continue;

		if (!mesh_rpc_call(n->id, n->addr, "roamd", "mesh_report", NULL, report_cb, c))
			report_cb(c, NULL, false);
	}

	poll_finish();
}

static bool net_roaming(const char *ssid)
{
	const struct mesh_network *net = mesh_network_by_ssid(ssid);

	return !net || net->roaming;
}

static bool node_has_net(const struct poll_node *n, const char *ssid, uint8_t band)
{
	unsigned int i;

	for (i = 0; i < n->n_ap; i++)
		if (!strcmp(n->ap[i].ssid, ssid) && mesh_band_bit(n->ap[i].band) == band)
			return true;

	return false;
}

static void member_call(const struct poll_node *n, const char *method, const char *args)
{
	if (!strcmp(n->id, SELF_ID)) {
		static struct blob_buf b;

		blob_buf_init(&b, 0);
		if (args && blobmsg_add_json_from_string(&b, args))
			roam_ubus_call_local(method, b.head);

		return;
	}

	mesh_rpc_call(n->id, n->addr, "roamd", method, args, NULL, NULL);
}

static struct poll_sta *ref_sta(const struct sta_ref *r)
{
	return &nodes[r->node].sta[r->sta];
}

static int ref_cmp(const void *a, const void *b)
{
	const struct sta_ref *ra = a, *rb = b;
	int diff = memcmp(ref_sta(ra)->addr, ref_sta(rb)->addr, 6);

	if (diff)
		return diff;

	if (ra->node != rb->node)
		return ra->node - rb->node;

	return ra->sta - rb->sta;
}

static void refs_build(void)
{
	unsigned int i, j;

	n_refs = 0;

	for (i = 0; i < n_nodes; i++)
		for (j = 0; j < nodes[i].n_sta; j++)
			refs[n_refs++] = (struct sta_ref){ .node = i, .sta = j };

	qsort(refs, n_refs, sizeof(refs[0]), ref_cmp);
}

static unsigned int group_end(unsigned int start)
{
	const uint8_t *addr = ref_sta(&refs[start])->addr;
	unsigned int end = start + 1;

	while (end < n_refs && !memcmp(ref_sta(&refs[end])->addr, addr, 6))
		end++;

	return end;
}

static void ghosts_drop(unsigned int from, unsigned int to)
{
	uint32_t oldest = 0;
	unsigned int k;

	for (k = from; k < to; k++) {
		const struct poll_sta *s = ref_sta(&refs[k]);

		if (s->client && s->connected && (!oldest || s->connected < oldest))
			oldest = s->connected;
	}

	for (k = from; k < to; k++) {
		struct poll_sta *s = ref_sta(&refs[k]);
		char args[64];

		if (!s->client || !s->connected || s->connected == oldest)
			continue;

		snprintf(args, sizeof(args), "{\"mac\":\"%s\"}", s->mac);
		member_call(&nodes[refs[k].node], "mesh_drop", args);
		s->connected = 0;
	}
}

#define PEER_JSON_MAX	12000

static void peer_clients_add(struct blob_buf *b, unsigned int self)
{
	unsigned int k;
	void *arr;

	arr = blobmsg_open_array(b, "clients");

	for (k = 0; k < n_refs && blob_len(b->head) < PEER_JSON_MAX; k++) {
		const struct poll_sta *s = ref_sta(&refs[k]);

		if (refs[k].node != self && s->client && s->connected)
			blobmsg_add_string(b, NULL, s->mac);
	}

	blobmsg_close_array(b, arr);
}

static void neighbors_push(void)
{
	static struct blob_buf b;
	unsigned int i, j;
	char *json;
	void *arr;

	for (i = 0; i < n_nodes; i++) {
		if (!nodes[i].online)
			continue;

		blob_buf_init(&b, 0);
		arr = blobmsg_open_array(&b, "neighbors");

		for (j = 0; j < n_nodes; j++) {
			unsigned int a;

			for (a = 0; a < nodes[j].n_ap; a++) {
				const struct poll_ap *ap = &nodes[j].ap[a];
				void *t;

				if (!ap->nr[0])
					continue;

				t = blobmsg_open_table(&b, NULL);
				blobmsg_add_string(&b, "bssid", ap->bssid);
				blobmsg_add_string(&b, "ssid", ap->ssid);
				blobmsg_add_string(&b, "nr", ap->nr);
				blobmsg_close_table(&b, t);
			}
		}

		blobmsg_close_array(&b, arr);
		peer_clients_add(&b, i);

		json = blobmsg_format_json(b.head, true);
		if (!json)
			continue;

		member_call(&nodes[i], "mesh_neighbors", json);
		free(json);
	}
}

static void cardinal_push(void)
{
	unsigned int i;
	char *json;

	cardinal_poll_done();

	json = cardinal_locks_json();
	if (!json)
		return;

	for (i = 0; i < n_nodes; i++)
		if (nodes[i].online && strcmp(nodes[i].id, SELF_ID))
			member_call(&nodes[i], "mesh_cardinal", json);

	free(json);
}

static unsigned int neighbor_list(const struct poll_node *best, const uint8_t *addr,
				  const char *ssid, uint8_t band, char *out, size_t len)
{
	unsigned int i, count = 0;
	size_t used = 0;

	for (i = 0; i < best->n_ap; i++) {
		const struct poll_ap *a = &best->ap[i];
		uint8_t bit = mesh_band_bit(a->band);

		if (!a->nr[0] || strcmp(a->ssid, ssid))
			continue;

		if (band && bit != band)
			continue;

		if (roam_admit(addr, best->id, mesh_band_from_bit(bit)) != ADMIT_OK)
			continue;

		if (used + strlen(a->nr) + 4 >= len)
			break;

		used += snprintf(out + used, len - used, "%s\"%s\"", count ? "," : "", a->nr);
		count++;
	}

	return count;
}

#define STEER_MEMO_MAX		64
#define STEER_REFUSED_HOLD	1800000

/*
 * What the controller last asked of each client, so that it does not repeat
 * the same move every poll. A sent request waits age_time for the client to
 * leave; a refusal (the node used up its attempts or cannot steer this
 * client) waits until the client reconnects or moves.
 */
struct steer_memo {
	uint8_t addr[6];
	char home[MESH_ID_MAX];
	char target[MESH_ID_MAX];
	uint8_t band;
	uint32_t connected;
	uint64_t at;
	bool refused;
};

struct steer_call {
	uint8_t addr[6];
	char home[MESH_ID_MAX];
};

static struct steer_memo steer_memo[STEER_MEMO_MAX];

static struct steer_memo *steer_memo_find(const uint8_t *addr)
{
	unsigned int i;

	for (i = 0; i < STEER_MEMO_MAX; i++)
		if (steer_memo[i].at && !memcmp(steer_memo[i].addr, addr, 6))
			return &steer_memo[i];

	return NULL;
}

static bool steer_memo_holds(const struct poll_sta *c, const char *home, const char *target)
{
	struct steer_memo *m = steer_memo_find(c->addr);
	uint64_t hold;

	if (!m)
		return false;

	hold = m->refused ? STEER_REFUSED_HOLD : config.age_time;

	if (strcmp(m->home, home) || strcmp(m->target, target) || m->band != c->band ||
	    c->connected < m->connected || roam_now - m->at >= hold) {
		m->at = 0;
		return false;
	}

	return true;
}

static struct steer_memo *steer_memo_put(const struct poll_sta *c, const char *home,
					 const char *target)
{
	struct steer_memo *m = steer_memo_find(c->addr);
	unsigned int i;

	if (!m) {
		m = &steer_memo[0];
		for (i = 1; i < STEER_MEMO_MAX && m->at; i++)
			if (steer_memo[i].at < m->at)
				m = &steer_memo[i];
	}

	memcpy(m->addr, c->addr, 6);
	snprintf(m->home, sizeof(m->home), "%s", home);
	snprintf(m->target, sizeof(m->target), "%s", target);
	m->band = c->band;
	m->connected = c->connected;
	m->at = roam_now ? roam_now : 1;
	m->refused = false;

	return m;
}

static void steer_memo_result(struct steer_memo *m, bool sent, const char *reason)
{
	char mac[MESH_MAC_MAX];

	if (sent || !m->at)
		return;

	m->refused = true;

	roam_mac_str(m->addr, mac, sizeof(mac));
	roam_log(ROAM_L_INFO, "mesh: %s did not move %s to %s (%s), not asking again for now",
		 m->home, mac, m->target, reason ? reason : "no answer");
}

/* The node reports how the client answered the last move request. */
static void steer_memo_answer(const struct poll_sta *c, const char *home)
{
	struct steer_memo *m = steer_memo_find(c->addr);
	char reason[48];

	if (!m || m->refused || !c->has_btm || !c->btm_status || strcmp(m->home, home))
		return;

	if ((uint64_t)c->btm_age * 1000 > roam_now - m->at)
		return;

	snprintf(reason, sizeof(reason), "client refused, status %d", c->btm_status);
	steer_memo_result(m, false, reason);
}

static void steer_call_cb(void *priv, struct blob_attr *result, bool ok)
{
	static const struct blobmsg_policy rp[2] = {
		{ "sent", BLOBMSG_TYPE_BOOL },
		{ "reason", BLOBMSG_TYPE_STRING },
	};
	struct steer_call *sc = priv;
	struct steer_memo *m = steer_memo_find(sc->addr);
	struct blob_attr *tb[2] = { NULL, NULL };

	if (m && !strcmp(m->home, sc->home)) {
		if (ok && result)
			blobmsg_parse(rp, 2, tb, blobmsg_data(result), blobmsg_data_len(result));

		/* Nodes before 1.3.1 answer with an empty table on success. */
		if (ok && !tb[0])
			steer_memo_result(m, true, NULL);
		else
			steer_memo_result(m, tb[0] && blobmsg_get_bool(tb[0]),
					  tb[1] ? blobmsg_get_string(tb[1]) :
					  ok ? NULL : "refused or unreachable");
	}

	free(sc);
}

static const struct poll_ap *ap_find(const struct poll_node *n, const char *ssid, uint8_t band)
{
	unsigned int i;

	for (i = 0; i < n->n_ap; i++)
		if (!strcmp(n->ap[i].ssid, ssid) && mesh_band_bit(n->ap[i].band) == band)
			return &n->ap[i];

	return NULL;
}

static const struct poll_meas *meas_find(const struct poll_sta *c, const char *bssid)
{
	unsigned int i;

	for (i = 0; i < c->n_meas; i++)
		if (!strcasecmp(c->meas[i].bssid, bssid))
			return &c->meas[i];

	return NULL;
}

/* 2.4 GHz has to be better by rssi_diff to win against 5 GHz. */
static int meas_score(int signal, uint8_t band)
{
	return mesh_band_from_bit(band) == BAND_LOW ? signal - config.rssi_diff : signal;
}

/*
 * Pick the target among the access points of other devices the client itself
 * measured, on any band. Returns false when the client measured none of them.
 */
static bool meas_pick(const struct poll_sta *c, unsigned int home, const struct poll_node **best,
		      uint8_t *best_band, int *best_signal, int *home_signal)
{
	const struct poll_ap *own = ap_find(&nodes[home], c->ssid, c->band);
	const struct poll_meas *m;
	int best_score = 0;
	bool measured = false;
	unsigned int i, j;

	*best = NULL;
	*home_signal = c->signal;
	if (own && (m = meas_find(c, own->bssid)))
		*home_signal = m->signal;

	for (i = 0; i < n_nodes; i++) {
		const struct poll_node *n = &nodes[i];

		if (i == home || !n->online)
			continue;

		for (j = 0; j < n->n_ap; j++) {
			const struct poll_ap *a = &n->ap[j];
			uint8_t bit = mesh_band_bit(a->band);
			int score;

			if (strcmp(a->ssid, c->ssid) || !(m = meas_find(c, a->bssid)))
				continue;

			measured = true;

			if (m->signal < config.rssi_low ||
			    roam_admit(c->addr, n->id, mesh_band_from_bit(bit)) != ADMIT_OK)
				continue;

			score = meas_score(m->signal, bit);
			if (!*best || score > best_score) {
				*best = n;
				*best_band = bit;
				*best_signal = m->signal;
				best_score = score;
			}
		}
	}

	if (*best && roam_admit(c->addr, nodes[home].id, mesh_band_from_bit(c->band)) == ADMIT_OK &&
	    best_score - meas_score(*home_signal, c->band) < config.node_rssi_diff)
		*best = NULL;

	return measured;
}

static void steer_client(unsigned int from, unsigned int to, unsigned int client)
{
	const struct poll_sta *c = ref_sta(&refs[client]);
	const char *mac = c->mac, *ssid = c->ssid;
	unsigned int home = refs[client].node, k;
	uint8_t band = c->band, to_band = c->band;
	enum roam_band rb = mesh_band_from_bit(band);
	const struct poll_node *best = NULL;
	int best_signal = 0, home_signal = 0;
	char args[1024], list[768];
	struct steer_memo *memo;

	if (!net_roaming(ssid))
		return;

	steer_memo_answer(c, nodes[home].id);

	if (c->btm_paused)
		return;

	if (meas_pick(c, home, &best, &to_band, &best_signal, &home_signal)) {
		if (!best)
			return;
		goto steer;
	}

	for (k = from; k < to; k++) {
		const struct poll_sta *s = ref_sta(&refs[k]);
		const struct poll_node *n = &nodes[refs[k].node];

		if (s->band != band || !n->online || !node_has_net(n, ssid, band) ||
		    roam_admit(c->addr, n->id, rb) != ADMIT_OK)
			continue;

		if (!best || s->signal > best_signal) {
			best = n;
			best_signal = s->signal;
		}

		if (refs[k].node == home)
			home_signal = s->signal;
	}

	if (!best || best == &nodes[home])
		return;

	if (roam_admit(c->addr, nodes[home].id, rb) == ADMIT_OK &&
	    best_signal - home_signal < config.node_rssi_diff)
		return;

steer:
	if (steer_memo_holds(c, nodes[home].id, best->id))
		return;

	list[0] = 0;
	if (!neighbor_list(best, c->addr, ssid, to_band, list, sizeof(list)))
		neighbor_list(best, c->addr, ssid, 0, list, sizeof(list));

	if (list[0])
		snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"id\":\"%s\",\"neighbors\":[%s]}",
			 mac, best->id, list);
	else
		snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"id\":\"%s\"}", mac, best->id);

	roam_log(ROAM_L_INFO,
		 "mesh: %s is heard better on %s (%s GHz, %d dBm) than on %s (%s GHz, %d dBm), moving",
		 mac, best->id, roam_band_name(mesh_band_from_bit(to_band)), best_signal,
		 nodes[home].id, roam_band_name(rb), home_signal);

	memo = steer_memo_put(c, nodes[home].id, best->id);

	if (!strcmp(nodes[home].id, SELF_ID)) {
		static struct blob_buf sb;
		const char *reason = NULL;
		bool sent = false;

		blob_buf_init(&sb, 0);
		if (blobmsg_add_json_from_string(&sb, args)) {
			struct blob_attr *tb[1];
			static const struct blobmsg_policy np = { "neighbors", BLOBMSG_TYPE_ARRAY };

			blobmsg_parse(&np, 1, tb, blob_data(sb.head), blob_len(sb.head));
			sent = mesh_node_steer(mac, best->id, tb[0], &reason);
		}

		steer_memo_result(memo, sent, reason);
		return;
	}

	{
		struct steer_call *sc = calloc(1, sizeof(*sc));

		if (sc) {
			memcpy(sc->addr, c->addr, 6);
			snprintf(sc->home, sizeof(sc->home), "%s", nodes[home].id);
		}

		if (!mesh_rpc_call(nodes[home].id, nodes[home].addr, "roamd", "mesh_steer", args,
				   sc ? steer_call_cb : NULL, sc))
			free(sc);
	}
}

static void steer_round(void)
{
	unsigned int start, end, k;

	refs_build();

	for (start = 0; start < n_refs; start = end) {
		end = group_end(start);
		ghosts_drop(start, end);

		for (k = start; k < end; k++) {
			const struct poll_sta *s = ref_sta(&refs[k]);

			if (s->client && s->ssid[0] && s->band)
				steer_client(start, end, k);
		}
	}

	neighbors_push();
}
