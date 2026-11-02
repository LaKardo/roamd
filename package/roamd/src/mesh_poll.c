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
	int alt_signal;
	uint32_t alt_age;
	uint32_t connected;
	uint8_t band;
	bool client;
	bool idle;
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
	bool nbr_empty;
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
static struct uloop_timeout poll_watchdog = { .cb = poll_watchdog_cb };

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

		bssid = mesh_attr_str(cur, "bssid");
		if (!bssid || !mesh_valid_mac(bssid) || !mesh_attr_field(cur, "signal", BLOBMSG_TYPE_INT32))
			continue;

		if ((uint64_t)mesh_attr_u32(cur, "age") * 1000 > roam_meas_fresh())
			continue;

		m = &s->meas[s->n_meas++];
		snprintf(m->bssid, sizeof(m->bssid), "%s", bssid);
		m->signal = (int)mesh_attr_u32(cur, "signal");
	}
}

#define ALT_SIGNAL_AGE	300

/* How the device heard the client lately on its other band, from probes. */
static void alt_collect(struct poll_sta *s, struct blob_attr *cur)
{
	bool low = mesh_band_from_bit(s->band) == BAND_LOW;
	const char *key = low ? "signal_5" : "signal_24";
	const char *age = low ? "signal_5_age" : "signal_24_age";

	s->alt_signal = ROAMD_NO_SIGNAL;
	if (!s->band || !mesh_attr_field(cur, key, BLOBMSG_TYPE_INT32) ||
	    mesh_attr_u32(cur, age) > ALT_SIGNAL_AGE)
		return;

	s->alt_signal = (int)mesh_attr_u32(cur, key);
	s->alt_age = mesh_attr_u32(cur, age);
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

		mac = mesh_attr_str(cur, "mac");
		if (!mac || !mesh_valid_mac(mac) || !mesh_attr_field(cur, "signal", BLOBMSG_TYPE_INT32))
			continue;

		ea = ether_aton(mac);
		if (!ea)
			continue;

		s = &n->sta[n->n_sta++];
		memset(s, 0, sizeof(*s));
		memcpy(s->addr, ea->ether_addr_octet, sizeof(s->addr));
		snprintf(s->mac, sizeof(s->mac), "%s", mac);
		ssid = mesh_attr_str(cur, "ssid");
		if (ssid)
			snprintf(s->ssid, sizeof(s->ssid), "%s", ssid);
		s->signal = (int)mesh_attr_u32(cur, "signal");
		s->connected = client ? mesh_attr_u32(cur, "connected") : 0;
		s->band = mesh_band_bit(mesh_attr_str(cur, "band"));
		s->client = client;
		s->idle = client && mesh_attr_u32(cur, "inactive") >= MESH_CLIENT_IDLE;

		if (client && mesh_attr_field(cur, "btm_status", BLOBMSG_TYPE_INT32)) {
			s->has_btm = true;
			s->btm_status = (int)mesh_attr_u32(cur, "btm_status");
			s->btm_age = mesh_attr_u32(cur, "btm_age");
		}
		s->btm_paused = client && mesh_attr_field(cur, "btm_paused", BLOBMSG_TYPE_BOOL);
		if (client) {
			meas_collect(s, mesh_attr_field(cur, "reports", BLOBMSG_TYPE_ARRAY));
			alt_collect(s, cur);
		}
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

		bssid = mesh_attr_str(cur, "bssid");
		ssid = mesh_attr_str(cur, "ssid");
		if (!bssid || !ssid || !mesh_valid_mac(bssid))
			continue;

		a = &n->ap[n->n_ap++];
		memset(a, 0, sizeof(*a));
		snprintf(a->bssid, sizeof(a->bssid), "%s", bssid);
		snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
		band = mesh_attr_str(cur, "band");
		if (band)
			snprintf(a->band, sizeof(a->band), "%s", band);
		nr = mesh_attr_str(cur, "nr");
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

	snprintf(path, sizeof(path), MESH_MEMBERS_RUN "/%s.json", n->id);
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

		snprintf(spath, sizeof(spath), MESH_MEMBERS_RUN "/%s.pkgsrc", n->id);
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
	const char *os = mesh_attr_str(report, "os_version");
	const char *arch = mesh_attr_str(report, "arch");
	const char *have = mesh_attr_str(report, "pkg_version");
	const char *have_ui = mesh_attr_str(report, "ui_version");
	struct mesh_pkg_meta meta;
	char branch[MESH_WORD_MAX];
	const char *dot;

	if (!os || !arch || !have)
		return false;

	dot = strrchr(os, '.');
	snprintf(branch, sizeof(branch), "%.*s", dot ? (int)(dot - os) : (int)strlen(os), os);

	if (mesh_pkg_wanted() && mesh_pkg_stale(branch, arch, MESH_PKG_MAIN))
		mesh_pkg_refresh(branch, arch, MESH_PKG_MAIN, NULL, NULL);

	if (mesh_pkg_known(branch, arch, MESH_PKG_MAIN, &meta) &&
	    mesh_pkg_newer(have, meta.version) > 0)
		return true;

	if (!have_ui)
		return false;

	if (mesh_pkg_wanted() && mesh_pkg_stale(branch, arch, MESH_PKG_UI))
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
	mesh_member_hostname(n->id, mesh_attr_str(result, "hostname"));
	sta_collect(n, mesh_attr_field(result, "clients", BLOBMSG_TYPE_ARRAY), true);
	sta_collect(n, mesh_attr_field(result, "heard", BLOBMSG_TYPE_ARRAY), false);
	ap_collect(n, mesh_attr_field(result, "aps", BLOBMSG_TYPE_ARRAY));
	/* nodes before 1.3.7 do not report it */
	n->nbr_empty = mesh_attr_field(result, "nbr_count", BLOBMSG_TYPE_INT32) &&
		       !mesh_attr_u32(result, "nbr_count");

	profile = mesh_attr_field(result, "profile", BLOBMSG_TYPE_TABLE);
	nets = mesh_attr_str(profile, "networks_sum");
	bh = mesh_attr_str(profile, "backhaul_ssid");

	if (profile_sum[0] && (!nets || strcmp(nets, profile_sum))) {
		issue = "networks";
		cons = "broken";
	} else if (mesh.backhaul_ssid[0] && (!bh || strcmp(bh, mesh.backhaul_ssid))) {
		issue = "backhaul";
		cons = "degraded";
	}

	member_file_write(n, result, cons, issue, member_update_available(result));

	{
		struct blob_attr *events = mesh_attr_field(result, "events", BLOBMSG_TYPE_ARRAY);

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

	sta_collect(n, mesh_root_field(&self, "clients", BLOBMSG_TYPE_ARRAY), true);
	sta_collect(n, mesh_root_field(&self, "heard", BLOBMSG_TYPE_ARRAY), false);
	ap_collect(n, mesh_root_field(&self, "aps", BLOBMSG_TYPE_ARRAY));
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
	/* with no networks of its own the controller has nothing to hold the nodes to */
	snprintf(profile_sum, sizeof(profile_sum), "%s",
		 sum && mesh_network_at(0) ? sum : "");

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

	mesh_dir_ensure(MESH_MEMBERS_RUN);

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

/*
 * A node keeps the list in memory only, so it is sent again after a while
 * even when nothing changed: the node may have restarted.
 */
#define NBR_RESEND	60000

struct nbr_sent {
	char id[MESH_ID_MAX];
	uint32_t sum;
	uint64_t at;
};

static struct nbr_sent nbr_sent[POLL_NODE_MAX];

static uint32_t text_sum(const char *s)
{
	uint32_t h = 5381;

	while (*s)
		h = h * 33 + (unsigned char)*s++;

	return h;
}

/* false when this node already has exactly this list */
static bool nbr_changed(const char *id, const char *json, bool force)
{
	struct nbr_sent *free_slot = NULL, *oldest = &nbr_sent[0], *e = NULL;
	uint32_t sum = text_sum(json);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(nbr_sent) && !e; i++) {
		if (!strcmp(nbr_sent[i].id, id))
			e = &nbr_sent[i];
		else if (!nbr_sent[i].id[0] && !free_slot)
			free_slot = &nbr_sent[i];
		else if (nbr_sent[i].at < oldest->at)
			oldest = &nbr_sent[i];
	}

	if (!e) {
		e = free_slot ? free_slot : oldest;
		snprintf(e->id, sizeof(e->id), "%s", id);
		e->at = 0;
	}

	if (!force && e->at && e->sum == sum && roam_now - e->at < NBR_RESEND)
		return false;

	e->sum = sum;
	e->at = roam_now ? roam_now : 1;

	return true;
}

static void neighbors_push(void)
{
	static struct blob_buf b;
	unsigned int i, j, count;
	char *json;
	void *arr;

	for (i = 0; i < n_nodes; i++) {
		if (!nodes[i].online) {
			nbr_changed(nodes[i].id, "", false);
			continue;
		}

		blob_buf_init(&b, 0);
		arr = blobmsg_open_array(&b, "neighbors");
		count = 0;

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
				count++;
			}
		}

		blobmsg_close_array(&b, arr);
		peer_clients_add(&b, i);

		json = blobmsg_format_json(b.head, true);
		if (!json)
			continue;

		/* an empty list on the node means it restarted and lost what it had */
		if (nbr_changed(nodes[i].id, json, count && nodes[i].nbr_empty))
			member_call(&nodes[i], "mesh_neighbors", json);
		free(json);
	}
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

static const struct poll_meas *meas_find(const struct poll_sta *c, const char *bssid);

#define TRAIL_MAX		64
#define FIX_INTERVAL		600000
#define PROBE_INTERVAL		300000
#define TRAIL_BACK_HOLD		120000

/*
 * Where each client was before its current place and when it was last moved
 * by a correction, so that corrections are rare and never send a client back
 * to the place it just left.
 */
static struct client_trail {
	uint8_t addr[6];
	char home[MESH_ID_MAX];
	uint8_t band;
	char prev[MESH_ID_MAX];
	uint8_t prev_band;
	uint64_t seen;
	uint64_t left_at;
	uint64_t fix_at;
	uint64_t probe_at;
	uint64_t band_at;
} trail[TRAIL_MAX];

static struct client_trail *trail_get(const struct poll_sta *c, const char *home)
{
	struct client_trail *t = NULL, *oldest = &trail[0];
	unsigned int i;

	for (i = 0; i < TRAIL_MAX; i++) {
		if (trail[i].seen && !memcmp(trail[i].addr, c->addr, 6)) {
			t = &trail[i];
			break;
		}
		if (trail[i].seen < oldest->seen)
			oldest = &trail[i];
	}

	if (!t) {
		t = oldest;
		memset(t, 0, sizeof(*t));
		memcpy(t->addr, c->addr, 6);
	} else if (strcmp(t->home, home) || t->band != c->band) {
		memcpy(t->prev, t->home, sizeof(t->prev));
		t->prev_band = t->band;
		t->left_at = roam_now ? roam_now : 1;
	}

	snprintf(t->home, sizeof(t->home), "%s", home);
	t->band = c->band;
	t->seen = roam_now ? roam_now : 1;

	return t;
}

static bool trail_left(const struct client_trail *t, const char *node, uint8_t band)
{
	return t->prev[0] && !strcmp(t->prev, node) && t->prev_band == band;
}

/* The client left that place only moments ago. */
static bool trail_left_recent(const struct client_trail *t, const char *node, uint8_t band)
{
	return trail_left(t, node, band) && roam_now - t->left_at < TRAIL_BACK_HOLD;
}

#define SYS_LIST_MAX		3
#define SYS_PREF_HIGH		128
#define SUBELEM_CAND_PREF	3

struct sys_cand {
	const char *nr;
	int signal;
	bool high;
	uint8_t pref;
};

/* Whether the neighbor report element already carries this subelement. */
static bool nr_has_subelem(const char *nr, unsigned int id)
{
	size_t len = strlen(nr), pos = 26;
	unsigned int sid, slen;

	while (pos + 4 <= len) {
		if (sscanf(nr + pos, "%2x%2x", &sid, &slen) != 2)
			return true;
		if (sid == id)
			return true;
		pos += 4 + slen * 2;
	}

	return false;
}

/* The best the client was heard by a node on a band lately, by probes or its own report. */
static int heard_signal(const struct poll_sta *c, unsigned int home, unsigned int from,
			unsigned int to, unsigned int node, uint8_t band, const char *bssid)
{
	const struct poll_meas *m;
	int best = ROAMD_NO_SIGNAL;
	unsigned int k;

	for (k = from; k < to; k++) {
		const struct poll_sta *s = ref_sta(&refs[k]);

		if (refs[k].node != node || s->client || s->band != band ||
		    s->signal == ROAMD_NO_SIGNAL)
			continue;

		if (best == ROAMD_NO_SIGNAL || s->signal > best)
			best = s->signal;
	}

	m = meas_find(c, bssid);
	if (m && (best == ROAMD_NO_SIGNAL || m->signal > best))
		best = m->signal;

	if (node == home && band != c->band &&
	    c->alt_signal != ROAMD_NO_SIGNAL && (best == ROAMD_NO_SIGNAL || c->alt_signal > best))
		best = c->alt_signal;

	return best;
}

static int sys_cand_cmp(const void *a, const void *b)
{
	const struct sys_cand *x = a, *y = b;

	return (int)y->pref - (int)x->pref;
}

/*
 * The access points of the system the client may use, except the one it is
 * on and the one it just left, ranked: 5 GHz above 2.4 GHz, then by how well
 * they heard the client. 2.4 GHz is left out when a 5 GHz access point heard
 * it well enough. A place heard no better than where the client is now is
 * left out, and so is the other band of the same device when it was not
 * heard at all: a weak client would only bounce between the two. The client
 * picks among the rest itself.
 */
#define WEAK_GAIN	3
#define TRAIL_BACK_GAIN	10

static unsigned int system_list(const struct poll_sta *c, unsigned int home, unsigned int from,
				unsigned int to, const struct client_trail *t,
				char *out, size_t len)
{
	struct sys_cand cand[POLL_NODE_MAX * POLL_AP_MAX];
	unsigned int i, j, n = 0, count = 0;
	bool high_ok = false;
	size_t used = 0;

	out[0] = 0;
	for (i = 0; i < n_nodes; i++) {
		const struct poll_node *nd = &nodes[i];

		if (!nd->online)
			continue;

		for (j = 0; j < nd->n_ap && n < ARRAY_SIZE(cand); j++) {
			const struct poll_ap *a = &nd->ap[j];
			uint8_t bit = mesh_band_bit(a->band);
			enum roam_band rb = mesh_band_from_bit(bit);
			struct sys_cand *e;
			int level, signal;

			if (!a->nr[0] || strcmp(a->ssid, c->ssid))
				continue;

			if (i == home && bit == c->band)
				continue;

			if (roam_admit(c->addr, nd->id, rb) != ADMIT_OK)
				continue;

			signal = heard_signal(c, home, from, to, i, bit, a->bssid);
			if (signal == ROAMD_NO_SIGNAL ? i == home :
			    c->signal != ROAMD_NO_SIGNAL && signal < c->signal + WEAK_GAIN)
				continue;

			/* back where it just came from only when that is clearly better */
			if (trail_left_recent(t, nd->id, bit) &&
			    (signal == ROAMD_NO_SIGNAL || c->signal == ROAMD_NO_SIGNAL ||
			     signal < c->signal + TRAIL_BACK_GAIN))
				continue;

			e = &cand[n++];
			e->nr = a->nr;
			e->high = rb == BAND_HIGH;
			e->signal = signal;

			level = e->signal == ROAMD_NO_SIGNAL ? 1 : e->signal + 100;
			if (level < 1)
				level = 1;
			if (level > 100)
				level = 100;
			e->pref = (e->high ? SYS_PREF_HIGH : 0) + level;

			if (e->high && e->signal != ROAMD_NO_SIGNAL && e->signal >= config.steer_rssi)
				high_ok = true;
		}
	}

	qsort(cand, n, sizeof(cand[0]), sys_cand_cmp);

	for (i = 0; i < n && count < SYS_LIST_MAX; i++) {
		const struct sys_cand *e = &cand[i];

		if (high_ok && !e->high)
			continue;

		if (used + strlen(e->nr) + 10 >= len)
			break;

		if (nr_has_subelem(e->nr, SUBELEM_CAND_PREF))
			used += snprintf(out + used, len - used, "%s\"%s\"",
					 count ? "," : "", e->nr);
		else
			used += snprintf(out + used, len - used, "%s\"%s%02x01%02x\"",
					 count ? "," : "", e->nr, SUBELEM_CAND_PREF, e->pref);
		count++;
	}

	return count;
}

#define STEER_MEMO_MAX		64
#define STEER_REFUSED_HOLD	1800000
#define STEER_WEAK_DROP		5
#define STEER_ANY		"*"

/*
 * What the controller last asked of each client, so that it does not repeat
 * the same move every poll. A sent request waits age_time for the client to
 * leave; a refusal (the node used up its attempts or cannot steer this
 * client) waits until the client reconnects or moves. A weak client that
 * refused to leave is asked again once its signal drops by STEER_WEAK_DROP.
 */
struct steer_memo {
	uint8_t addr[6];
	char home[MESH_ID_MAX];
	char target[MESH_ID_MAX];
	uint8_t band;
	int signal;
	uint32_t connected;
	uint64_t at;
	bool refused;
};

struct steer_call {
	uint8_t addr[6];
	char home[MESH_ID_MAX];
	char *args;
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
	if (m->refused && !strcmp(target, STEER_ANY))
		hold = c->signal > m->signal - STEER_WEAK_DROP ? UINT64_MAX : 0;

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
	m->signal = c->signal;
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
	roam_log(ROAM_L_INFO, "mesh: %s did not move %s to %s (%s, %d dBm), not asking again for now",
		 m->home, mac, strcmp(m->target, STEER_ANY) ? m->target : "another access point",
		 reason ? reason : "no answer", m->signal);
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

/* With steer_deny every device turns the client away from the places it was not offered. */
static void deny_push(const char *args)
{
	unsigned int i;

	if (!config.steer_deny || !strstr(args, "\"neighbors\""))
		return;

	for (i = 0; i < n_nodes; i++)
		if (nodes[i].online)
			member_call(&nodes[i], "mesh_deny", args);
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
		bool sent;

		if (ok && result)
			blobmsg_parse(rp, 2, tb, blobmsg_data(result), blobmsg_data_len(result));

		sent = tb[0] && blobmsg_get_bool(tb[0]);
		steer_memo_result(m, sent, tb[1] ? blobmsg_get_string(tb[1]) :
				  ok ? NULL : "refused or unreachable");
		if (sent && sc->args)
			deny_push(sc->args);
	}

	free(sc->args);
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

/*
 * The client measured a clearly better access point elsewhere than the one
 * it chose itself: one request with that single target.
 */
static bool fix_pick(const struct poll_sta *c, unsigned int home, const struct client_trail *t,
		     const struct poll_node **best, uint8_t *best_band, int *best_signal,
		     int *home_signal)
{
	if ((uint64_t)c->connected * 1000 < config.hold_time)
		return false;

	if (t->fix_at && roam_now - t->fix_at < FIX_INTERVAL)
		return false;

	if (!meas_pick(c, home, best, best_band, best_signal, home_signal) || !*best)
		return false;

	return !trail_left(t, (*best)->id, *best_band);
}

/* Another device hears the client's probes clearly better on the same band. */
static bool probe_pick(const struct poll_sta *c, unsigned int home, unsigned int from,
		       unsigned int to, const struct client_trail *t,
		       const struct poll_node **best, int *best_signal, int *home_signal)
{
	enum roam_band rb = mesh_band_from_bit(c->band);
	unsigned int k;

	if (t->probe_at && roam_now - t->probe_at < PROBE_INTERVAL)
		return false;

	*best = NULL;
	*home_signal = c->signal;

	for (k = from; k < to; k++) {
		const struct poll_sta *s = ref_sta(&refs[k]);
		const struct poll_node *n = &nodes[refs[k].node];

		if (refs[k].node == home || s->band != c->band || !n->online ||
		    !node_has_net(n, c->ssid, c->band) ||
		    roam_admit(c->addr, n->id, rb) != ADMIT_OK)
			continue;

		if (!*best || s->signal > *best_signal) {
			*best = n;
			*best_signal = s->signal;
		}
	}

	if (!*best || *best_signal - *home_signal < config.node_rssi_diff)
		return false;

	return !trail_left(t, (*best)->id, c->band);
}

static void steer_send(const struct poll_sta *c, unsigned int home, const char *target,
		       const char *args, struct steer_memo *memo)
{
	if (!strcmp(nodes[home].id, SELF_ID)) {
		static const struct blobmsg_policy np = { "neighbors", BLOBMSG_TYPE_ARRAY };
		static struct blob_buf sb;
		const char *reason = NULL;
		bool sent = false;

		blob_buf_init(&sb, 0);
		if (blobmsg_add_json_from_string(&sb, args)) {
			struct blob_attr *tb[1];

			blobmsg_parse(&np, 1, tb, blob_data(sb.head), blob_len(sb.head));
			sent = mesh_node_steer(c->mac, target, tb[0], &reason);
		}

		steer_memo_result(memo, sent, reason);
		if (sent)
			deny_push(args);
		return;
	}

	{
		struct steer_call *sc = calloc(1, sizeof(*sc));

		if (sc) {
			memcpy(sc->addr, c->addr, 6);
			snprintf(sc->home, sizeof(sc->home), "%s", nodes[home].id);
			if (config.steer_deny)
				sc->args = strdup(args);
		}

		if (!mesh_rpc_call(nodes[home].id, nodes[home].addr, "roamd", "mesh_steer", args,
				   sc ? steer_call_cb : NULL, sc) && sc) {
			free(sc->args);
			free(sc);
		}
	}
}

/*
 * The client is weak where it is: ask it to leave and let it pick the
 * access point itself from the list of the system.
 */
static void steer_weak(const struct poll_sta *c, unsigned int home, unsigned int from,
		       unsigned int to, const struct client_trail *t)
{
	char args[1024], list[768];
	struct steer_memo *memo;

	if (steer_memo_holds(c, nodes[home].id, STEER_ANY))
		return;

	if (!system_list(c, home, from, to, t, list, sizeof(list)))
		return;

	snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"neighbors\":[%s]}", c->mac, list);

	roam_log(ROAM_L_INFO, "mesh: %s is weak on %s (%s GHz, %d dBm), asking it to move",
		 c->mac, nodes[home].id, roam_band_name(mesh_band_from_bit(c->band)), c->signal);

	memo = steer_memo_put(c, nodes[home].id, STEER_ANY);
	steer_send(c, home, NULL, args, memo);
}

#define BAND_UP_INTERVAL	600000
#define BAND_UP_MARGIN		10
#define BAND_UP_FRESH		30
#define BAND_UP_FAIL_HOLD	3600000

/*
 * A client on 2.4 GHz that its own device heard well on 5 GHz moments ago:
 * one request to move up, then BAND_UP_INTERVAL of quiet whatever the answer.
 * The 5 GHz signal has to be BAND_UP_MARGIN above steer_rssi, so the client
 * is not weak there right after the move.
 */
static bool steer_band_up(const struct poll_sta *c, unsigned int home, struct client_trail *t)
{
	const struct poll_node *n = &nodes[home];
	uint8_t high = MESH_BAND_5;
	char args[1024], list[768];
	struct steer_memo *memo;
	int need = config.rssi_good;

	if (!config.band_steering || config.prefer != PREFER_HIGH)
		return false;

	if (mesh_band_from_bit(c->band) != BAND_LOW || c->alt_signal == ROAMD_NO_SIGNAL ||
	    c->alt_age > BAND_UP_FRESH)
		return false;

	if (need < config.steer_rssi + BAND_UP_MARGIN)
		need = config.steer_rssi + BAND_UP_MARGIN;
	if (c->alt_signal < need)
		return false;

	if ((uint64_t)c->connected * 1000 < config.hold_time)
		return false;

	if (t->band_at && roam_now - t->band_at < BAND_UP_INTERVAL)
		return false;

	/* it came back down after the last move up: 5 GHz does not hold here */
	if (t->band_at && trail_left(t, n->id, high) && roam_now - t->band_at < BAND_UP_FAIL_HOLD)
		return false;

	if (trail_left_recent(t, n->id, high) ||
	    roam_admit(c->addr, n->id, BAND_HIGH) != ADMIT_OK)
		return false;

	if (!neighbor_list(n, c->addr, c->ssid, high, list, sizeof(list)))
		return false;

	t->band_at = roam_now ? roam_now : 1;

	snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"id\":\"%s\",\"neighbors\":[%s]}",
		 c->mac, n->id, list);

	roam_log(ROAM_L_INFO, "mesh: %s is heard on 5 GHz of %s at %d dBm (2.4 GHz %d dBm), moving it up",
		 c->mac, n->id, c->alt_signal, c->signal);

	memo = steer_memo_put(c, n->id, n->id);
	steer_send(c, home, n->id, args, memo);

	return true;
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
	struct client_trail *t;
	struct steer_memo *memo;
	bool home_ok, fix = false, probe = false;

	if (!net_roaming(ssid))
		return;

	t = trail_get(c, nodes[home].id);
	steer_memo_answer(c, nodes[home].id);

	if (c->btm_paused || c->idle)
		return;

	home_ok = roam_admit(c->addr, nodes[home].id, rb) == ADMIT_OK;
	if (home_ok && c->signal != ROAMD_NO_SIGNAL) {
		if (c->signal >= config.steer_rssi && steer_band_up(c, home, t))
			return;

		if (c->signal > config.steer_rssi_max)
			return;

		if (c->signal < config.steer_rssi) {
			steer_weak(c, home, from, to, t);
			return;
		}
	}

	if (home_ok) {
		if (fix_pick(c, home, t, &best, &to_band, &best_signal, &home_signal)) {
			fix = true;
			goto steer;
		}
		to_band = band;
		if (probe_pick(c, home, from, to, t, &best, &best_signal, &home_signal)) {
			probe = true;
			goto steer;
		}
		return;
	}

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

	if (home_ok && best_signal - home_signal < config.node_rssi_diff)
		return;

steer:
	if (steer_memo_holds(c, nodes[home].id, best->id))
		return;

	list[0] = 0;
	if (!neighbor_list(best, c->addr, ssid, to_band, list, sizeof(list)) && !fix)
		neighbor_list(best, c->addr, ssid, 0, list, sizeof(list));

	if (list[0])
		snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"id\":\"%s\",\"neighbors\":[%s]}",
			 mac, best->id, list);
	else
		snprintf(args, sizeof(args), "{\"mac\":\"%s\",\"id\":\"%s\"}", mac, best->id);

	roam_log(ROAM_L_INFO,
		 "mesh: %s is heard better on %s (%s GHz, %d dBm) than on %s (%s GHz, %d dBm), %s",
		 mac, best->id, roam_band_name(mesh_band_from_bit(to_band)), best_signal,
		 nodes[home].id, roam_band_name(rb), home_signal,
		 fix ? "correcting its choice" : "moving");

	if (fix)
		t->fix_at = roam_now ? roam_now : 1;
	if (probe)
		t->probe_at = roam_now ? roam_now : 1;

	memo = steer_memo_put(c, nodes[home].id, best->id);
	steer_send(c, home, best->id, args, memo);
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
