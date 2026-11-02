#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "roamd.h"
#include "mesh.h"

#define BTM_VALIDITY_PERIOD	100
#define BTM_MBO_LOW_RSSI	5
#define BTM_MBO_UNSPECIFIED	0
#define BTM_CELL_PREF		0
#define KICK_REASON		5
#define STEER_RETRY_INTERVAL	5000
#define BEACON_REQ_PER_POLL	4
#define BEACON_POLL_PER_POLL	2
#define INSIST_LOG_INTERVAL	1800000
#define INSIST_LOG_SLOTS	32
#define BTM_REFUSE_SLOTS	64
#define BTM_REFUSE_LIMIT	3
#define BTM_REFUSE_HOLD		1800000
#define BTM_REJECT_CANDIDATES	6
#define BTM_REJECT_NO_CANDIDATE	7

static struct blob_buf b;

/* Probe-only stations are forgotten after age_time, so remember log times apart. */
static bool insist_log_due(const uint8_t *addr)
{
	static struct {
		uint8_t addr[6];
		uint64_t at;
	} slot[INSIST_LOG_SLOTS];
	unsigned int i, oldest = 0;

	for (i = 0; i < INSIST_LOG_SLOTS; i++) {
		if (!memcmp(slot[i].addr, addr, 6) && slot[i].at) {
			if (roam_now - slot[i].at < INSIST_LOG_INTERVAL)
				return false;

			slot[i].at = roam_now;
			return true;
		}

		if (slot[i].at < slot[oldest].at)
			oldest = i;
	}

	memcpy(slot[oldest].addr, addr, 6);
	slot[oldest].at = roam_now;

	return true;
}

static enum roam_band preferred_band(void)
{
	return config.prefer == PREFER_LOW ? BAND_LOW : BAND_HIGH;
}

static const char *bss_nr_string(const struct roam_bss *bss)
{
	static const struct blobmsg_policy policy[3] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[3];

	if (!bss->nr)
		return NULL;

	blobmsg_parse_array(policy, 3, tb, blobmsg_data(bss->nr), blobmsg_data_len(bss->nr));
	if (!tb[2])
		return NULL;

	return blobmsg_get_string(tb[2]);
}

static bool band_info_fresh(const struct roam_sta_band *info, enum roam_band band)
{
	if (!info->present || info->signal == ROAMD_NO_SIGNAL)
		return false;

	return roam_now - info->seen <= config.age_time;
}

#define DENY_SLOTS		16
#define DENY_ALLOW_MAX		8
#define DENY_TIME		15000
#define DENY_TRIES		3

/*
 * Right after a move request the access points that were not offered turn
 * the client away for a short while, so that it goes where it was asked to.
 * A client that keeps knocking is let in after DENY_TRIES attempts.
 */
static struct {
	uint8_t addr[6];
	uint8_t allow[DENY_ALLOW_MAX][6];
	unsigned int n_allow;
	unsigned int tries;
	uint64_t until;
} deny[DENY_SLOTS];

void roam_policy_deny(const uint8_t *addr, struct blob_attr *neighbors)
{
	unsigned int i, slot = 0;
	struct blob_attr *cur;
	int rem;

	for (i = 0; i < DENY_SLOTS; i++) {
		if (!memcmp(deny[i].addr, addr, 6)) {
			slot = i;
			break;
		}
		if (deny[i].until < deny[slot].until)
			slot = i;
	}

	memset(&deny[slot], 0, sizeof(deny[slot]));
	memcpy(deny[slot].addr, addr, 6);

	if (neighbors)
		blobmsg_for_each_attr(cur, neighbors, rem) {
			const char *nr;
			uint8_t *a;

			if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING ||
			    deny[slot].n_allow >= DENY_ALLOW_MAX)
				continue;

			nr = blobmsg_get_string(cur);
			if (strlen(nr) < 12)
				continue;

			a = deny[slot].allow[deny[slot].n_allow];
			if (sscanf(nr, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
				   &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) == 6)
				deny[slot].n_allow++;
		}

	if (deny[slot].n_allow)
		deny[slot].until = roam_now + DENY_TIME;
}

static bool deny_holds(struct roam_sta *sta, struct roam_bss *bss, enum roam_event ev)
{
	unsigned int i, j;

	for (i = 0; i < DENY_SLOTS; i++) {
		if (!deny[i].until || memcmp(deny[i].addr, sta->addr, 6))
			continue;

		if (roam_now >= deny[i].until)
			return false;

		for (j = 0; j < deny[i].n_allow; j++)
			if (!memcmp(deny[i].allow[j], bss->bssid, 6))
				return false;

		if (ev != EVENT_PROBE && ++deny[i].tries >= DENY_TRIES) {
			deny[i].until = 0;
			roam_log(ROAM_L_INFO, "roamd: %s keeps knocking on %s GHz, letting it in",
				 sta->mac, roam_band_name(bss->band));
			return false;
		}

		return true;
	}

	return false;
}

bool roam_policy_allow(struct roam_sta *sta, struct roam_bss *bss, enum roam_event ev)
{
	struct roam_sta_band *pref, *cur;
	enum roam_band want;

	if (!config.enabled || !roam_bss_matches(bss))
		return true;

	if (roam_admit(sta->addr, mesh_self_node_id(), bss->band) != ADMIT_OK)
		return false;

	if (deny_holds(sta, bss, ev))
		return false;

	if (ev == EVENT_ASSOC || !roam_bss_target(bss))
		return true;

	if (!config.band_steering || config.prefer == PREFER_NONE || !config.deny_probe)
		return true;

	want = preferred_band();
	if (bss->band == want) {
		sta->band[want == BAND_HIGH ? BAND_LOW : BAND_HIGH].deny_start = 0;
		return true;
	}

	pref = &sta->band[want];
	cur = &sta->band[bss->band];

	if (roam_now < cur->allow_until)
		return true;

	if (cur->deny_start && roam_now - cur->deny_start > config.deny_time + config.age_time)
		cur->deny_start = 0;

	if (!pref->present || roam_now - pref->seen > config.check_time[want])
		goto allow;

	if (pref->signal == ROAMD_NO_SIGNAL || pref->signal < config.rssi_low)
		goto allow;

	if (pref->signal < config.rssi_good)
		goto allow;

	if (cur->signal != ROAMD_NO_SIGNAL && cur->signal - pref->signal >= config.rssi_diff)
		goto allow;

	if (ev == EVENT_PROBE && mesh_peer_client(sta->addr))
		return false;

	if (!cur->deny_start)
		cur->deny_start = roam_now;

	if (roam_now - cur->deny_start < config.deny_time)
		return false;

	cur->deny_start = 0;
	cur->allow_until = roam_now + config.age_time;

	if (insist_log_due(sta->addr))
		roam_log(ROAM_L_INFO, "roamd: %s insists on %s GHz, giving up",
			 sta->mac, roam_band_name(bss->band));

	return true;

allow:
	cur->deny_start = 0;
	return true;
}

/*
 * hostapd refuses a beacon request in a mode the client did not advertise;
 * many Apple and Intel clients offer passive and table only. A passive scan
 * waits for a beacon, hence the longer duration.
 */
static bool beacon_req_mode(const struct roam_sta *sta, uint32_t *mode, uint32_t *duration)
{
	if (sta->rrm_modes & RRM_BEACON_ACTIVE) {
		*mode = BEACON_MODE_ACTIVE;
		*duration = 50;
	} else if (sta->rrm_modes & RRM_BEACON_PASSIVE) {
		*mode = BEACON_MODE_PASSIVE;
		*duration = 120;
	} else if (sta->rrm_modes & RRM_BEACON_TABLE) {
		*mode = BEACON_MODE_TABLE;
		*duration = 0;
	} else {
		return false;
	}

	return true;
}

static void policy_beacon_request(struct roam_sta *sta, struct roam_bss *from, struct roam_bss *to,
				  unsigned int *budget)
{
	uint32_t mode, duration;

	if (!sta->rrm || !config.neighbor_reports || !to->op_class)
		return;

	if (!beacon_req_mode(sta, &mode, &duration))
		return;

	if (sta->beacon_req_silent >= config.steer_retries)
		return;

	if (roam_now - sta->last_beacon_req < config.beacon_req_interval)
		return;

	if (!*budget)
		return;

	(*budget)--;

	sta->last_beacon_req = roam_now;
	sta->beacon_req_silent++;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "addr", sta->mac);
	blobmsg_add_string(&b, "ssid", to->ssid);
	blobmsg_add_u32(&b, "mode", mode);
	blobmsg_add_u32(&b, "duration", duration);
	blobmsg_add_u32(&b, "channel", to->channel);
	blobmsg_add_u32(&b, "op_class", to->op_class);
	roam_bss_invoke(from, "rrm_beacon_req", &b);
}

/* Low RSSI is the reason only when the client is weak: one that hears its AP well may ignore it. */
uint8_t roam_policy_mbo_reason(int signal)
{
	return signal != ROAMD_NO_SIGNAL && signal < config.steer_rssi ?
	       BTM_MBO_LOW_RSSI : BTM_MBO_UNSPECIFIED;
}

static void policy_btm(struct roam_sta *sta, struct roam_bss *from, struct roam_bss *to)
{
	const char *nr = bss_nr_string(to);
	void *list;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "addr", sta->mac);
	blobmsg_add_u32(&b, "dialog_token", roam_policy_btm_token(sta));
	blobmsg_add_u8(&b, "disassociation_imminent", 0);
	blobmsg_add_u32(&b, "disassociation_timer", 0);
	blobmsg_add_u32(&b, "reassoc_delay", 0);

	blobmsg_add_u8(&b, "abridged", 1);
	blobmsg_add_u32(&b, "validity_period", BTM_VALIDITY_PERIOD);
	blobmsg_add_u32(&b, "mbo_reason", roam_policy_mbo_reason(sta->band[from->band].signal));
	blobmsg_add_u32(&b, "cell_pref", BTM_CELL_PREF);

	list = blobmsg_open_array(&b, "neighbors");
	if (nr)
		blobmsg_add_string(&b, NULL, nr);
	blobmsg_close_array(&b, list);

	roam_bss_invoke(from, "bss_transition_request", &b);

	sta->last_steer = roam_now;
	sta->steer_from = from->band;
	sta->steer_count++;

	mesh_log_local(sta->mac, from->band, to->band, NULL, MESH_EV_STEER);

	roam_log(ROAM_L_INFO, "roamd: steering %s from %s GHz to %s GHz (attempt %u of %u)",
		 sta->mac, roam_band_name(from->band), roam_band_name(to->band),
		 sta->steer_count, config.steer_retries);
}

static void sta_del_client(struct roam_sta *sta, struct roam_bss *from)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "addr", sta->mac);
	blobmsg_add_u32(&b, "reason", KICK_REASON);
	blobmsg_add_u8(&b, "deauth", 1);
	blobmsg_add_u32(&b, "ban_time", config.deny_time);
	roam_bss_invoke(from, "del_client", &b);

	roam_sta_reset(sta);
}

static void policy_evict(struct roam_sta *sta, struct roam_bss *from, enum roam_admit verdict)
{
	bool node = verdict == ADMIT_DENY_NODE;

	roam_log(ROAM_L_INFO, "roamd: %s is not allowed %s, disconnecting from %s (%s GHz)",
		 sta->mac, node ? "on this device" : "on this band",
		 from->ifname, roam_band_name(from->band));

	mesh_log_local(sta->mac, from->band, MESH_BAND_NA, NULL,
		       node ? MESH_EV_DENY_NODE : MESH_EV_DENY_BAND);

	sta_del_client(sta, from);
}

void roam_policy_kick(struct roam_sta *sta, struct roam_bss *from)
{
	roam_log(ROAM_L_INFO, "roamd: disconnecting %s from %s (%s GHz)",
		 sta->mac, from->ifname, roam_band_name(from->band));

	sta->last_steer = roam_now;
	sta->steer_from = from->band;
	sta->steer_count++;

	mesh_log_local(sta->mac, from->band, MESH_BAND_NA, NULL, MESH_EV_KICK);
	sta_del_client(sta, from);
}

bool roam_policy_can_steer(const struct roam_sta *sta)
{
	if (sta->steer_count >= config.steer_retries)
		return false;

	if (roam_policy_btm_paused(sta->addr))
		return false;

	return !sta->last_steer || roam_now - sta->last_steer >= STEER_RETRY_INTERVAL;
}

/*
 * Clients that keep refusing to move, kept by address because the station
 * entry is reset on every reconnect. After BTM_REFUSE_LIMIT refusals in
 * BTM_REFUSE_HOLD the client is left alone for BTM_REFUSE_HOLD.
 */
static struct {
	uint8_t addr[6];
	uint32_t count;
	uint64_t last;
	uint64_t paused_until;
} refusals[BTM_REFUSE_SLOTS];

static int refusal_find(const uint8_t *addr, bool create)
{
	unsigned int i, oldest = 0;

	for (i = 0; i < BTM_REFUSE_SLOTS; i++) {
		if (refusals[i].last && !memcmp(refusals[i].addr, addr, 6))
			return i;

		if (refusals[i].last < refusals[oldest].last)
			oldest = i;
	}

	if (!create)
		return -1;

	memset(&refusals[oldest], 0, sizeof(refusals[oldest]));
	memcpy(refusals[oldest].addr, addr, 6);

	return oldest;
}

bool roam_policy_btm_paused(const uint8_t *addr)
{
	int i = refusal_find(addr, false);

	return i >= 0 && refusals[i].paused_until && roam_now < refusals[i].paused_until;
}

uint32_t roam_policy_btm_rejects(const uint8_t *addr)
{
	int i = refusal_find(addr, false);

	if (i < 0 || roam_now - refusals[i].last >= BTM_REFUSE_HOLD)
		return 0;

	return refusals[i].count;
}

static void refusal_note(struct roam_sta *sta, int status)
{
	int i;

	if (!status) {
		i = refusal_find(sta->addr, false);
		if (i >= 0)
			memset(&refusals[i], 0, sizeof(refusals[i]));
		return;
	}

	if (status != BTM_REJECT_CANDIDATES && status != BTM_REJECT_NO_CANDIDATE)
		return;

	i = refusal_find(sta->addr, true);
	if (roam_now - refusals[i].last >= BTM_REFUSE_HOLD)
		refusals[i].count = 0;

	refusals[i].last = roam_now ? roam_now : 1;
	if (++refusals[i].count < BTM_REFUSE_LIMIT)
		return;

	refusals[i].count = 0;
	refusals[i].paused_until = roam_now + BTM_REFUSE_HOLD;

	roam_log(ROAM_L_INFO, "roamd: %s refused to move %u times, leaving it alone for %u min",
		 sta->mac, BTM_REFUSE_LIMIT, BTM_REFUSE_HOLD / 60000);
}

/* The token a BSS Transition Management request carries, so that the answer can be matched. */
uint8_t roam_policy_btm_token(struct roam_sta *sta)
{
	if (!++sta->dialog_token)
		sta->dialog_token = 1;

	sta->btm_token = sta->dialog_token;
	sta->btm_sent_at = roam_now ? roam_now : 1;

	return sta->btm_token;
}

static const char *btm_status_text(int status)
{
	switch (status) {
	case 0:
		return "accepted";
	case 1:
		return "rejected, no reason given";
	case 2:
		return "rejected, not enough beacons";
	case 3:
		return "rejected, not enough capacity";
	case 4:
		return "rejected, termination undesired";
	case 5:
		return "rejected, termination delay";
	case 6:
		return "rejected, candidate list provided";
	case 7:
		return "rejected, no suitable candidate";
	case 8:
		return "rejected, leaving the network";
	default:
		return "rejected";
	}
}

void roam_policy_btm_response(struct roam_sta *sta, struct roam_bss *bss, int token, int status,
			      const char *target)
{
	if (!sta->btm_sent_at || (token >= 0 && token != sta->btm_token))
		return;

	sta->btm_sent_at = 0;
	sta->btm_status = status;
	sta->btm_status_at = roam_now ? roam_now : 1;

	roam_log(ROAM_L_INFO, "roamd: %s answered the move request on %s GHz at %d dBm: %s (%d)%s%s",
		 sta->mac, roam_band_name(bss->band), sta->band[bss->band].signal,
		 btm_status_text(status), status,
		 target && target[0] ? ", to " : "", target ? target : "");

	refusal_note(sta, status);
}

static bool sta_should_leave(struct roam_sta *sta, struct roam_bss *bss,
			     struct roam_bss *target)
{
	enum roam_band want = preferred_band();
	int here = sta->band[bss->band].signal;
	int there;

	if (!band_info_fresh(&sta->band[target->band], target->band))
		return false;

	there = sta->band[target->band].signal;

	if (here != ROAMD_NO_SIGNAL && here < config.kick_rssi)
		return there > here;

	if (here != ROAMD_NO_SIGNAL && there - here >= config.rssi_diff)
		return true;

	if (bss->band == want) {
		if (here == ROAMD_NO_SIGNAL || here >= config.rssi_low)
			return false;

		return there > here;
	}

	if (want == BAND_HIGH && !sta->band[bss->band].ht)
		return false;

	if (there < config.rssi_good)
		return false;

	return here == ROAMD_NO_SIGNAL || here - there < config.rssi_diff;
}

/* Remote APs are measured in turn, so a measurement lives a few poll rounds. */
uint64_t roam_meas_fresh(void)
{
	uint64_t t = (uint64_t)config.beacon_poll_interval * 4;

	return t > config.age_time ? t : config.age_time;
}

/*
 * Ask each 802.11k client in turn how it hears the access points of the
 * other devices, one remote AP per request, so the controller can compare
 * places the client is not heard from.
 */
static void policy_beacon_poll(struct roam_bss *bss, unsigned int *budget)
{
	struct mesh_nbr_info nbr[ROAMD_MAX_NEIGHBORS];
	struct roam_sta *sta;
	unsigned int n;

	if (!config.beacon_poll_interval || !config.neighbor_reports)
		return;

	n = mesh_neighbors_remote(bss->ssid, nbr, ARRAY_SIZE(nbr) - 1);
	if (!n)
		return;

	/* The own access point too, so that both sides of the comparison come from the client. */
	if (bss->op_class && bss->channel) {
		memcpy(nbr[n].bssid, bss->bssid, 6);
		nbr[n].op_class = bss->op_class;
		nbr[n].channel = bss->channel;
		n++;
	}

	avl_for_each_element(&roam_sta_tree, sta, avl) {
		const struct mesh_nbr_info *to;
		uint32_t mode, duration;
		char bssid[18];

		if (!*budget)
			return;

		if (sta->bss != bss || !sta->rrm || !beacon_req_mode(sta, &mode, &duration))
			continue;

		if (roam_now - sta->connected_since < config.hold_time)
			continue;

		if (sta->beacon_req_silent >= config.steer_retries)
			continue;

		if (sta->last_poll_req && roam_now - sta->last_poll_req < config.beacon_poll_interval)
			continue;

		if (roam_now - sta->last_beacon_req < config.beacon_req_interval)
			continue;

		to = &nbr[sta->poll_next++ % n];
		roam_mac_str(to->bssid, bssid, sizeof(bssid));

		(*budget)--;
		sta->last_poll_req = roam_now;
		sta->last_beacon_req = roam_now;
		sta->beacon_req_silent++;

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "addr", sta->mac);
		blobmsg_add_string(&b, "ssid", bss->ssid);
		blobmsg_add_string(&b, "bssid", bssid);
		blobmsg_add_u32(&b, "mode", mode);
		blobmsg_add_u32(&b, "duration", duration);
		blobmsg_add_u32(&b, "channel", to->channel);
		blobmsg_add_u32(&b, "op_class", to->op_class);
		roam_bss_invoke(bss, "rrm_beacon_req", &b);
	}
}

#define ONCE_QUIET		600000
#define ONCE_INTERVAL		900000

/*
 * A client in the middle range that has not scanned for a while gets one
 * beacon request, so the controller learns how it hears the other devices.
 */
static void policy_beacon_once(struct roam_bss *bss, unsigned int *budget)
{
	struct mesh_nbr_info nbr[ROAMD_MAX_NEIGHBORS];
	struct roam_sta *sta;
	unsigned int n;

	if (!config.beacon_once || !config.neighbor_reports)
		return;

	n = mesh_neighbors_remote(bss->ssid, nbr, ARRAY_SIZE(nbr));
	if (!n)
		return;

	avl_for_each_element(&roam_sta_tree, sta, avl) {
		const struct mesh_nbr_info *to;
		uint32_t mode, duration;
		uint64_t quiet_since;
		int signal;
		char bssid[18];

		if (!*budget)
			return;

		if (sta->bss != bss || !sta->rrm || !beacon_req_mode(sta, &mode, &duration))
			continue;

		signal = sta->band[bss->band].signal;
		if (signal == ROAMD_NO_SIGNAL || signal > config.steer_rssi_max ||
		    signal < config.steer_rssi)
			continue;

		quiet_since = sta->last_probe > sta->connected_since ?
			      sta->last_probe : sta->connected_since;
		if (roam_now - quiet_since < ONCE_QUIET)
			continue;

		if (sta->last_once && roam_now - sta->last_once < ONCE_INTERVAL)
			continue;

		if (roam_now - sta->last_beacon_req < config.beacon_req_interval)
			continue;

		to = &nbr[sta->poll_next++ % n];
		roam_mac_str(to->bssid, bssid, sizeof(bssid));

		(*budget)--;
		sta->last_once = roam_now;
		sta->last_beacon_req = roam_now;

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "addr", sta->mac);
		blobmsg_add_string(&b, "ssid", bss->ssid);
		blobmsg_add_string(&b, "bssid", bssid);
		blobmsg_add_u32(&b, "mode", mode);
		blobmsg_add_u32(&b, "duration", duration);
		blobmsg_add_u32(&b, "channel", to->channel);
		blobmsg_add_u32(&b, "op_class", to->op_class);
		roam_bss_invoke(bss, "rrm_beacon_req", &b);
	}
}

void roam_policy_run(struct roam_bss *bss)
{
	unsigned int beacon_budget = BEACON_REQ_PER_POLL;
	unsigned int poll_budget = BEACON_POLL_PER_POLL;
	struct roam_bss *target;
	struct roam_sta *sta;

	if (!config.enabled)
		return;

	avl_for_each_element(&roam_sta_tree, sta, avl) {
		enum roam_admit verdict;

		if (sta->bss != bss)
			continue;

		verdict = roam_admit(sta->addr, mesh_self_node_id(), bss->band);
		if (verdict != ADMIT_OK)
			policy_evict(sta, bss, verdict);
	}

	policy_beacon_poll(bss, &poll_budget);
	policy_beacon_once(bss, &poll_budget);

	/* In a mesh the controller decides where clients go, across devices and bands. */
	if (mesh.enabled && (mesh.role == MESH_NODE || !list_empty(&mesh_members)))
		return;

	if (!config.bss_transition || !config.band_steering || config.prefer == PREFER_NONE)
		return;

	target = roam_bss_target(bss);
	if (!target)
		return;

	avl_for_each_element(&roam_sta_tree, sta, avl) {
		if (sta->bss != bss)
			continue;

		if (roam_admit(sta->addr, mesh_self_node_id(), target->band) != ADMIT_OK)
			continue;

		if (roam_now - sta->connected_since < config.hold_time)
			continue;

		if (sta->give_up_until) {
			if (roam_now < sta->give_up_until)
				continue;

			sta->give_up_until = 0;
		}

		if (!roam_policy_can_steer(sta))
			continue;

		if (!band_info_fresh(&sta->band[target->band], target->band))
			policy_beacon_request(sta, bss, target, &beacon_budget);

		if (!sta_should_leave(sta, bss, target))
			continue;

		if (!sta->btm) {
			if (config.allow_kick)
				roam_policy_kick(sta, bss);
			continue;
		}

		policy_btm(sta, bss, target);
	}
}
