#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <libubox/uloop.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_LINK_GRACE_AIR	20000
#define MESH_ATTACH_GRACE	45000
#define MESH_LINK_GRACE_CABLE	10000
#define MESH_UPSTREAM_PATIENCE	60000
#define MESH_PARENT_PROBATION	60000
#define MESH_PARENT_PENALTY	600000
#define MESH_CABLE_HOLD		30000
#define MESH_CABLE_PROOF	120000
#define MESH_CABLE_PENALTY	600000
#define MESH_WEAK_HOLD		600000
#define MESH_RESCAN_GAP		600000
#define MESH_LINK_SAMPLE	60000
#define MESH_BH_SCAN_RETRY	30000
#define MESH_SIGNAL_STRONG	-65
#define MESH_BH_STA		"mesh_bh_sta"
#define MESH_LINK_SAMPLE_GAP	3000

enum bh_class {
	BH_WEAK,
	BH_USABLE,
	BH_STRONG
};

struct bh_parent {
	char bssid[MESH_MAC_MAX];
	const char *chain;
	int depth;
	int band;
	int signal;
	unsigned int samples;
};

struct bh_penalty {
	char owner[MESH_ID_MAX];
	uint64_t until;
};

static void bh_scan_done(void);

/* what the node knows about its wireless backhaul between watchdog ticks */
struct bh_state {
	struct uloop_timeout scan_timer;
	bool up;
	int band;
	int bss_on;
	char parent[MESH_MAC_MAX];
	char parent_owner[MESH_ID_MAX];
	uint64_t since;
	uint64_t link_down_since;
	uint64_t link_sample_at;
	uint64_t weak_since;
	bool weak_attach;
	uint64_t rescan_at;
	uint64_t scan_at;
	bool scan_busy;
	bool scan_heard;
	bool scan_empty;
	bool scan_rescan;
	bool scan_move;
	bool want_search;
	uint64_t cable_since;
	uint64_t cable_dropped_at;
	uint64_t cable_penalty_until;
	char uplink_port[sizeof(((struct mesh_uplink *)0)->ifname)];
	char parents_seen[MESH_BH_PARENTS_LEN];
	struct bh_penalty penalties[MESH_BH_PARENT_MAX];
};

static struct bh_state bh = { .bss_on = -1 };

/* candidate parents, rebuilt from the profile on every load */
static char bh_parents_buf[MESH_BH_PARENTS_LEN];
static struct bh_parent bh_parents[MESH_BH_PARENT_MAX];
static unsigned int bh_parents_n;
static const char *bh_radio(struct uci_context *ctx, struct uci_package *pkg, int band)
{
	static const char *const want[] = { "2g", "5g" };
	struct uci_element *e;

	if (band < 0 || band > 1)
		return NULL;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		const char *b;

		if (strcmp(s->type, "wifi-device"))
			continue;

		b = uci_lookup_option_string(ctx, s, "band");
		if (b && !strcmp(b, want[band]))
			return s->e.name;
	}

	return NULL;
}

static bool bh_sta_apply(int band, const char *bssid, bool enabled)
{
	struct uci_session u;
	const char *radio;
	bool changed;

	if (!mesh.backhaul_ssid[0] || !mesh.backhaul_key[0])
		return false;

	if (!uci_session_open(&u, "wireless"))
		return false;

	radio = bh_radio(u.ctx, u.pkg, band);
	if (!radio || !uci_session_add(&u, "wifi-iface", MESH_BH_STA)) {
		uci_session_close(&u);
		return false;
	}

	uci_session_set(&u, MESH_BH_STA, "device", radio);
	uci_session_set(&u, MESH_BH_STA, "mode", "sta");
	uci_session_set(&u, MESH_BH_STA, "network", "lan");
	uci_session_set(&u, MESH_BH_STA, "encryption", "psk2");
	uci_session_set(&u, MESH_BH_STA, "wds", "1");
	uci_session_set(&u, MESH_BH_STA, "ssid", mesh.backhaul_ssid);
	uci_session_set(&u, MESH_BH_STA, "key", mesh.backhaul_key);
	if (bssid[0])
		uci_session_set(&u, MESH_BH_STA, "bssid", bssid);
	uci_session_set(&u, MESH_BH_STA, "disabled", enabled ? "0" : "1");

	changed = u.dirty;
	uci_session_close(&u);

	if (!changed)
		return true;

	roam_log(ROAM_L_INFO, "mesh: backhaul station %s on %s GHz",
		 enabled ? "up" : "down", band ? "5" : "2.4");

	roam_network_reload("backhaul station");

	return true;
}

static char bh_limit_nodes[MESH_BH_ALLOW_LEN];
static bool bh_limit_void;

static void bh_limit_load(void)
{
	char buf[MESH_BH_LIMITS_LEN], *save = NULL, *tok;

	bh_limit_nodes[0] = 0;

	if (!mesh.bh_limits[0] || !mesh.member_id[0])
		return;

	snprintf(buf, sizeof(buf), "%s", mesh.bh_limits);

	for (tok = strtok_r(buf, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		char *nodes = strchr(tok, '/');

		if (!nodes)
			continue;

		*nodes++ = 0;

		if (strcmp(tok, mesh.member_id))
			continue;

		snprintf(bh_limit_nodes, sizeof(bh_limit_nodes), "%s", nodes);

		return;
	}
}

static bool bh_owner_allowed(const char *owner)
{
	char buf[MESH_BH_ALLOW_LEN], *save = NULL, *tok;

	if (!bh_limit_nodes[0])
		return true;

	snprintf(buf, sizeof(buf), "%s", bh_limit_nodes);

	for (tok = strtok_r(buf, "-", &save); tok; tok = strtok_r(NULL, "-", &save))
		if (!strcmp(tok, owner))
			return true;

	return false;
}

static const char *bh_owner(const struct bh_parent *p)
{
	const char *dash = strrchr(p->chain, '-');

	if (dash)
		return dash + 1;

	return p->chain[0] ? p->chain : MESH_CONTROLLER_OWNER;
}

static bool bh_radio_present[2];

static void bh_parents_fill(void)
{
	char *save, *tok;

	bh_parents_n = 0;
	snprintf(bh_parents_buf, sizeof(bh_parents_buf), "%s", mesh.backhaul_parents);

	for (tok = strtok_r(bh_parents_buf, " ", &save);
	     tok && bh_parents_n < MESH_BH_PARENT_MAX;
	     tok = strtok_r(NULL, " ", &save)) {
		struct bh_parent *p = &bh_parents[bh_parents_n];
		char *depth = strchr(tok, '/');
		char *chain = depth ? strchr(depth + 1, '/') : NULL;
		char *band = chain ? strchr(chain + 1, '/') : NULL;

		if (!band)
			continue;

		*depth++ = '\0';
		*chain++ = '\0';
		*band++ = '\0';

		p->band = !strcmp(band, "5");
		if (!bh_radio_present[p->band] || mesh_chain_has(chain, mesh.member_id))
			continue;

		snprintf(p->bssid, sizeof(p->bssid), "%s", tok);
		p->chain = chain;

		if (!bh_owner_allowed(bh_owner(p)))
			continue;

		p->depth = atoi(depth);
		p->signal = ROAMD_NO_SIGNAL;
		p->samples = 0;
		bh_parents_n++;
	}
}

static void bh_parents_load(void)
{
	struct uci_session u;

	bh_radio_present[0] = false;
	bh_radio_present[1] = false;

	if (uci_session_open(&u, "wireless")) {
		bh_radio_present[0] = bh_radio(u.ctx, u.pkg, 0) != NULL;
		bh_radio_present[1] = bh_radio(u.ctx, u.pkg, 1) != NULL;
		uci_session_close(&u);
	}

	bh_limit_load();
	bh_parents_fill();

	if (!bh_parents_n && bh_limit_nodes[0]) {
		if (!bh_limit_void) {
			bh_limit_void = true;
			roam_log(ROAM_L_INFO,
				 "mesh: allowed parents (%s) are not reachable, the limit is ignored",
				 bh_limit_nodes);
		}

		bh_limit_nodes[0] = '\0';
		bh_parents_fill();
	} else if (bh_parents_n) {
		bh_limit_void = false;
	}

	roam_log(ROAM_L_DEBUG, "mesh: %u backhaul parent(s) allowed (nodes %s)",
		 bh_parents_n, bh_limit_nodes[0] ? bh_limit_nodes : "any");
}

static void bh_owner_restore(void)
{
	unsigned int i;

	bh.parent_owner[0] = '\0';
	bh_parents_load();

	for (i = 0; i < bh_parents_n; i++) {
		if (strcasecmp(bh_parents[i].bssid, bh.parent))
			continue;

		snprintf(bh.parent_owner, sizeof(bh.parent_owner), "%s", bh_owner(&bh_parents[i]));
		return;
	}
}

static bool bh_penalized(const char *owner)
{
	unsigned int i;

	for (i = 0; i < MESH_BH_PARENT_MAX; i++)
		if (bh.penalties[i].until > roam_now && !strcmp(bh.penalties[i].owner, owner))
			return true;

	return false;
}

static void bh_penalize(const char *why)
{
	struct bh_penalty *slot = &bh.penalties[0];
	unsigned int i;

	if (!bh.parent_owner[0])
		return;

	for (i = 0; i < MESH_BH_PARENT_MAX; i++) {
		if (!strcmp(bh.penalties[i].owner, bh.parent_owner)) {
			slot = &bh.penalties[i];
			break;
		}

		if (bh.penalties[i].until < slot->until)
			slot = &bh.penalties[i];
	}

	snprintf(slot->owner, sizeof(slot->owner), "%s", bh.parent_owner);
	slot->until = roam_now + MESH_PARENT_PENALTY;

	roam_log(ROAM_L_INFO, "mesh: backhaul parent %s %s, avoided for 10 minutes", bh.parent, why);
}

static bool scan_sample(const char *bssid, int signal)
{
	unsigned int i;
	bool heard = false;

	for (i = 0; i < bh_parents_n; i++) {
		struct bh_parent *p = &bh_parents[i];

		if (strcasecmp(p->bssid, bssid))
			continue;

		if (!p->samples || signal < p->signal)
			p->signal = signal;

		p->samples++;
		heard = true;
	}

	return heard;
}

static void scan_heard(const char *bssid, int signal)
{
	bh.scan_heard |= scan_sample(bssid, signal);
}

static void scan_second_cb(struct uloop_timeout *t);

static void scan_first_done(void)
{
	bh.scan_timer.cb = scan_second_cb;
	uloop_timeout_set(&bh.scan_timer, MESH_LINK_SAMPLE_GAP);
}

static bool bh_scan_start(bool rescan)
{
	unsigned int i;

	if (!bh_parents_n)
		return false;

	for (i = 0; i < bh_parents_n; i++)
		bh_parents[i].samples = 0;

	bh.scan_heard = false;
	bh.scan_rescan = rescan;
	bh.scan_busy = true;

	mesh_bh_scan(scan_heard, scan_first_done);

	return true;
}

static enum bh_class bh_class_of(int signal, bool stable)
{
	if (!stable || signal < mesh.backhaul_min_signal)
		return BH_WEAK;

	return signal >= MESH_SIGNAL_STRONG ? BH_STRONG : BH_USABLE;
}

static enum bh_class bh_class(const struct bh_parent *p)
{
	return bh_class_of(p->signal, p->samples > 1);
}

static int bh_band_pick(int i24, int i5)
{
	if (i5 < 0)
		return i24;

	if (i24 < 0 || (bh_parents[i5].signal >= mesh.backhaul_min_signal &&
			bh_parents[i5].signal >= bh_parents[i24].signal - mesh.backhaul_delta))
		return i5;

	return i24;
}

static bool bh_better(int a, int b)
{
	const struct bh_parent *pa = &bh_parents[a], *pb;
	enum bh_class ca, cb;

	if (b < 0)
		return true;

	pb = &bh_parents[b];
	ca = bh_class(pa);
	cb = bh_class(pb);

	if (ca != cb)
		return ca > cb;

	if (pa->depth != pb->depth)
		return pa->depth < pb->depth;

	return pa->signal > pb->signal;
}

static int bh_choose(bool allow_penalized)
{
	bool done[MESH_BH_PARENT_MAX] = { false };
	unsigned int i, j;
	int best = -1;

	for (i = 0; i < bh_parents_n; i++) {
		bool skip = !allow_penalized && bh_penalized(bh_owner(&bh_parents[i]));
		int i24 = -1, i5 = -1, pick;

		if (done[i])
			continue;

		for (j = i; j < bh_parents_n; j++) {
			const struct bh_parent *p = &bh_parents[j];
			int *slot;

			if (strcmp(p->chain, bh_parents[i].chain))
				continue;

			done[j] = true;
			if (skip || !p->samples)
				continue;

			slot = p->band ? &i5 : &i24;
			if (*slot < 0 || p->signal > bh_parents[*slot].signal)
				*slot = j;
		}

		pick = bh_band_pick(i24, i5);
		if (pick >= 0 && bh_better(pick, best))
			best = pick;
	}

	return best;
}

static int bh_select(void)
{
	int best = bh_choose(false);

	return best >= 0 ? best : bh_choose(true);
}

static void bh_attach(int idx, const char *why)
{
	const struct bh_parent *p = &bh_parents[idx];

	if (!bh_sta_apply(p->band, p->bssid, true))
		return;

	roam_log(ROAM_L_INFO, "mesh: backhaul parent %s %s: %s GHz, %d dBm, %d hop(s) from the controller",
		 p->bssid, why, p->band ? "5" : "2.4", p->signal, p->depth + 1);

	snprintf(bh.parent, sizeof(bh.parent), "%s", p->bssid);
	snprintf(bh.parent_owner, sizeof(bh.parent_owner), "%s", bh_owner(p));
	bh.band = p->band;
	bh.up = true;
	bh.since = roam_now;
	bh.link_down_since = roam_now;
	bh.link_sample_at = roam_now;
	bh.want_search = false;
	bh.scan_empty = false;
	bh.cable_since = 0;
	bh.weak_since = 0;
	bh.weak_attach = bh_class(p) == BH_WEAK;
}

static void bh_detach(bool search, const char *why)
{
	if (bh.up)
		roam_log(ROAM_L_INFO, "mesh: leaving backhaul parent %s: %s",
			 bh.parent[0] ? bh.parent : "?", why);

	if (bh_sta_apply(bh.band, bh.parent, false))
		bh.up = false;
	bh.want_search = search;
	bh.cable_since = 0;
}

static void bh_no_parent(void)
{
	if (!bh.scan_empty)
		roam_log(ROAM_L_INFO, "mesh: no backhaul parent in range");

	bh.scan_empty = true;
}

static bool bh_no_path(void)
{
	return mesh_node_contact_lost() &&
	       (bh.scan_empty || roam_now - mesh_node_last_contact() >= MESH_UPSTREAM_PATIENCE);
}

static void bh_bss_ensure(bool relay)
{
	bool up = relay && mesh.backhaul_enabled &&
		  mesh.backhaul_ssid[0] && mesh.backhaul_key[0];

	if (bh.bss_on == (int)up)
		return;

	mesh_backhaul_bss_set(up);
	bh.bss_on = up;

	roam_log(ROAM_L_INFO, "mesh: backhaul network %s by this node", up ? "relayed" : "not relayed");
}

static bool bh_is_weak(void)
{
	return bh.weak_attach || (bh.weak_since && roam_now - bh.weak_since >= MESH_WEAK_HOLD);
}

static void bh_sample_link(void)
{
	struct mesh_iw_link l;
	int signal;

	if (roam_now - bh.link_sample_at < MESH_LINK_SAMPLE)
		return;

	bh.link_sample_at = roam_now;

	if (!mesh_uplink_any(&l) || !l.signal)
		return;

	signal = l.signal;

	if (bh_class_of(signal, true) != BH_WEAK) {
		bh.weak_since = 0;
		bh.weak_attach = false;
	} else if (!bh.weak_since) {
		bh.weak_since = roam_now;
	}
}

static void bh_search(void)
{
	if (bh.scan_busy || (bh.scan_empty && roam_now - bh.scan_at < MESH_BH_SCAN_RETRY))
		return;

	bh_parents_load();
	bh.scan_at = roam_now;

	if (!bh_scan_start(false))
		bh_no_parent();
}

static void bh_scan_done(void)
{
	int best;
	unsigned int i, seen = 0;

	roam_time_update();
	bh.scan_busy = false;

	for (i = 0; i < bh_parents_n; i++)
		if (bh_parents[i].samples)
			seen++;

	roam_log(ROAM_L_DEBUG, "mesh: scan finished, %u of %u parent(s) heard", seen, bh_parents_n);

	best = bh.scan_heard ? bh_select() : -1;

	if (bh.scan_move) {
		bh.scan_move = false;

		if (best >= 0)
			bh_attach(best, "replaces a parent that is no longer allowed");
		else
			bh_detach(true, "it is no longer allowed and no other parent was heard");

		return;
	}

	if (bh.scan_rescan) {
		if (bh.up && best >= 0 && bh_class(&bh_parents[best]) != BH_WEAK &&
		    strcasecmp(bh_parents[best].bssid, bh.parent))
			bh_attach(best, "gives a stronger link");
		return;
	}

	if (bh.up || !mesh.backhaul_enabled || !mesh_node_contact_lost())
		return;

	if (best < 0) {
		bh_no_parent();
		return;
	}

	bh_attach(best, "chosen");
}

static void scan_second_cb(struct uloop_timeout *t)
{
	mesh_bh_scan(scan_heard, bh_scan_done);
}

static void bh_weak_rescan(void)
{
	roam_time_update();

	if (!bh.up || !bh_is_weak() || mesh_node_contact_lost() || bh.scan_busy)
		return;

	if (bh.rescan_at && roam_now - bh.rescan_at < MESH_RESCAN_GAP)
		return;

	bh.rescan_at = roam_now;
	bh_parents_load();
	bh_scan_start(true);
}

static bool uplink_alive(void)
{
	if (bh.up)
		return mesh_bridge_sta_up();

	if (bh.uplink_port[0] && !mesh_bridge_carrier(bh.uplink_port))
		return false;

	return !mesh_bridge_root_is_self(MESH_BRIDGE);
}

static void bh_linked(void)
{
	struct mesh_uplink up;

	bh.scan_empty = false;
	bh.want_search = false;

	if (bh.cable_dropped_at && roam_now - bh.cable_dropped_at >= MESH_CABLE_PROOF)
		bh.cable_dropped_at = 0;

	if (!bh.up) {
		if (mesh_node_uplink(&up) && !up.wireless)
			snprintf(bh.uplink_port, sizeof(bh.uplink_port), "%s", up.ifname);
		return;
	}

	bh_sample_link();

	if (bh.cable_penalty_until > roam_now || !mesh_node_wired_uplink()) {
		bh.cable_since = 0;
		return;
	}

	if (!bh.cable_since) {
		bh.cable_since = roam_now;
		return;
	}

	if (roam_now - bh.cable_since < MESH_CABLE_HOLD)
		return;

	bh_detach(false, "cable reaches the controller");
	bh.cable_dropped_at = roam_now;
}

static uint64_t air_grace(void)
{
	return roam_now - bh.since < 2 * MESH_ATTACH_GRACE ? MESH_ATTACH_GRACE : MESH_LINK_GRACE_AIR;
}

static void bh_lost(bool alive)
{
	if (!mesh.backhaul_enabled)
		return;

	if (bh.cable_dropped_at) {
		bh.cable_dropped_at = 0;
		bh.cable_penalty_until = roam_now + MESH_CABLE_PENALTY;
		bh.want_search = true;
		roam_log(ROAM_L_INFO, "mesh: cable lost the controller right after taking over, "
			 "staying on the air for 10 minutes");
	}

	if (bh.want_search) {
		bh_search();
		return;
	}

	if (bh.up && mesh_node_last_contact() < bh.since) {
		if (!alive && roam_now - bh.link_down_since >= air_grace()) {
			bh_penalize("did not accept the station");
			bh_detach(true, "the station was not accepted");
		} else if (alive && roam_now - bh.since >= MESH_PARENT_PROBATION) {
			bh_penalize("did not reach the controller");
			bh_detach(true, "no contact with the controller through it");
		}
		return;
	}

	if (alive) {
		if (roam_now - mesh_node_last_contact() < MESH_UPSTREAM_PATIENCE)
			return;

		if (bh.up) {
			bh_penalize("lost the controller");
			bh_detach(true, "the controller is lost");
			return;
		}

		bh_search();
		return;
	}

	if (roam_now - bh.link_down_since < (bh.up ? air_grace() : MESH_LINK_GRACE_CABLE))
		return;

	if (bh.up) {
		bh_detach(true, "the link is down");
		return;
	}

	bh_search();
}

void mesh_bh_restore(void)
{
	struct uci_session u;
	struct uci_section *sta;

	if (!uci_session_open(&u, "wireless"))
		return;

	sta = uci_lookup_section(u.ctx, u.pkg, MESH_BH_STA);

	if (sta && !roam_uci_bool(uci_lookup_option_string(u.ctx, sta, "disabled"))) {
		const char *device = uci_lookup_option_string(u.ctx, sta, "device");
		const char *bssid = uci_lookup_option_string(u.ctx, sta, "bssid");
		const char *radio = bh_radio(u.ctx, u.pkg, 1);

		snprintf(bh.parent, sizeof(bh.parent), "%s", bssid ? bssid : "");
		bh.up = true;
		bh.since = roam_now;
		bh.band = device && radio && !strcmp(device, radio);
	}

	uci_session_close(&u);

	if (bh.up)
		bh_owner_restore();
}

void mesh_bh_limit_enforce(void)
{
	unsigned int i;

	if (!bh.up || !bh.parent[0] || !mesh.backhaul_parents[0] || bh.scan_busy)
		return;

	bh_parents_load();

	for (i = 0; i < bh_parents_n; i++)
		if (!strcasecmp(bh_parents[i].bssid, bh.parent))
			return;

	if (!bh_parents_n) {
		roam_log(ROAM_L_INFO,
			 "mesh: no allowed parent to move to, keeping the link through %s",
			 bh.parent);

		return;
	}

	roam_log(ROAM_L_INFO, "mesh: backhaul parent %s is no longer allowed, looking for another one",
		 bh.parent);

	bh.scan_move = true;

	if (!bh_scan_start(true)) {
		bh.scan_move = false;
		bh_detach(true, "it is no longer allowed and a scan could not start");
	}
}

/* the link toward the controller; also restarts the grace when a new station shows up */
bool mesh_bh_link_check(void)
{
	static int sta_seen;
	int sta = mesh_bridge_sta_ifindex();
	bool alive = uplink_alive();

	/* a new station interface restarts the grace; a missing one must not keep restarting it */
	if (alive)
		bh.link_down_since = 0;
	else if (!bh.link_down_since || (bh.up && sta && sta != sta_seen))
		bh.link_down_since = roam_now;

	sta_seen = sta;

	if (!mesh.backhaul_enabled && bh.up)
		bh_detach(false, "wireless backhaul is turned off");

	return alive;
}

/* one watchdog step; true when this node still has a path to relay */
bool mesh_bh_step(bool alive)
{
	if (mesh_node_contact_lost())
		bh_lost(alive);
	else
		bh_linked();

	return !bh_no_path();
}

void mesh_bh_relay(bool relay)
{
	bh_bss_ensure(relay);
}

void mesh_bh_profile_applied(void)
{
	if (bh.bss_on == 1)
		mesh_backhaul_bss_set(true);

	if (strcmp(bh.parents_seen, mesh.backhaul_parents)) {
		snprintf(bh.parents_seen, sizeof(bh.parents_seen), "%s", mesh.backhaul_parents);
		bh_weak_rescan();
	}
}

void mesh_bh_blob(struct blob_buf *b)
{
	blobmsg_add_u8(b, "bh_up", bh.up);
	blobmsg_add_string(b, "bh_parent", bh.parent);
	blobmsg_add_string(b, "bh_band", bh.band ? "5" : "2.4");
	if (bh.up)
		blobmsg_add_u32(b, "bh_age", (uint32_t)((roam_now - bh.since) / 1000));
	if (bh.link_down_since)
		blobmsg_add_u32(b, "link_down", (uint32_t)((roam_now - bh.link_down_since) / 1000));
	blobmsg_add_u8(b, "want_search", bh.want_search);
	blobmsg_add_u8(b, "scan_busy", bh.scan_busy);
}

const char *mesh_bh_uplink_port(void)
{
	return bh.uplink_port;
}