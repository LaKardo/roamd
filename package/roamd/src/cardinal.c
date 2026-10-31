#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/ether.h>
#include <libubox/blobmsg_json.h>

#include "roamd.h"
#include "mesh.h"

#define CARDINAL_MAX		64
#define CARDINAL_TICK		2000
#define CARDINAL_FRESH		5000
#define CARDINAL_GONE_TICKS	3
#define CARDINAL_REMOTE_TTL	45000
#define CARDINAL_IDLE		600000

enum cardinal_where {
	WHERE_NONE,
	WHERE_LOCAL,
	WHERE_REMOTE
};

struct cardinal_entry {
	struct avl_node avl;
	uint8_t addr[6];
	char mac[18];
	uint8_t band;
	bool blocked;
	bool ever_seen;
	uint8_t where;
	uint8_t gone;
	uint32_t error_count;
	uint32_t poll_gen;
	int last_signal;
	bool estimated;
	uint64_t stable_since;
	uint64_t last_sample;
	uint64_t touched;
	uint64_t sample_seen;
	uint64_t pushed_until;
};

static struct avl_tree cardinal_tree;
static struct uloop_timeout cardinal_timer;
static uint32_t cardinal_poll_gen;

static int addr_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, 6);
}

static bool cardinal_decides(void)
{
	return config.cardinal && config.enabled && config.prefer != PREFER_NONE &&
	       (!mesh.enabled || mesh.role == MESH_CONTROLLER);
}

static enum roam_band cardinal_target(void)
{
	return config.prefer == PREFER_LOW ? BAND_LOW : BAND_HIGH;
}

static void entry_free(struct cardinal_entry *e)
{
	avl_delete(&cardinal_tree, &e->avl);
	free(e);
}

static struct cardinal_entry *entry_get(const uint8_t *addr, bool create)
{
	struct cardinal_entry *e, *tmp, *idle = NULL;

	e = avl_find_element(&cardinal_tree, addr, e, avl);
	if (e || !create)
		return e;

	if (cardinal_tree.count >= CARDINAL_MAX) {
		avl_for_each_element_safe(&cardinal_tree, e, avl, tmp)
			if (!e->blocked && !e->pushed_until &&
			    (!idle || e->touched < idle->touched))
				idle = e;

		if (!idle)
			return NULL;

		entry_free(idle);
	}

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	memcpy(e->addr, addr, 6);
	roam_mac_str(addr, e->mac, sizeof(e->mac));
	e->avl.key = e->addr;
	e->stable_since = roam_now;
	e->touched = roam_now;
	e->band = BAND_MAX;
	avl_insert(&cardinal_tree, &e->avl);

	return e;
}

static enum roam_band other_band(enum roam_band band)
{
	return band == BAND_HIGH ? BAND_LOW : BAND_HIGH;
}

static void entry_set(struct cardinal_entry *e, bool blocked, const char *why)
{
	enum roam_band target = cardinal_target();

	if (e->blocked == blocked)
		return;

	e->blocked = blocked;
	e->band = blocked ? target : BAND_MAX;
	e->stable_since = roam_now;
	e->error_count = 0;

	roam_log(ROAM_L_INFO, "roamd: cardinal: %s %s %s GHz (%s)", e->mac,
		 blocked ? "held on" : "released from", roam_band_name(target), why);
	mesh_log_local(e->mac, other_band(target), target, NULL,
		       blocked ? MESH_EV_CARDINAL_ON : MESH_EV_CARDINAL_OFF);
}

static bool manual_rule(const uint8_t *addr)
{
	return roam_device_lock(addr) != LOCK_NONE;
}

static void entry_sample(struct cardinal_entry *e, int signal, bool estimated)
{
	e->last_signal = signal;
	e->estimated = estimated;
	e->last_sample = roam_now;
	e->touched = roam_now;
	e->gone = 0;

	if (signal < config.rssi_low) {
		if (e->error_count < config.cardinal_error_max)
			e->error_count++;
		e->stable_since = roam_now;
	} else {
		e->error_count = 0;
	}

	if (!e->blocked && e->ever_seen &&
	    roam_now - e->stable_since >= config.cardinal_window &&
	    mesh_band_usable(roam_band_bit(cardinal_target())))
		entry_set(e, true, "steady signal");

	if (e->blocked && signal < config.kick_rssi)
		entry_set(e, false, "signal below kick_rssi");
	else if (e->blocked && e->error_count >= config.cardinal_error_max)
		entry_set(e, false, "weak signal");
}

static bool sample_pick(const int *sig, const uint32_t *age_ms, int *out, bool *estimated)
{
	enum roam_band target = cardinal_target(), other = other_band(target);

	if (sig[target] != ROAMD_NO_SIGNAL && age_ms[target] <= CARDINAL_FRESH) {
		*out = sig[target];
		*estimated = false;
		return true;
	}

	if (sig[other] != ROAMD_NO_SIGNAL && age_ms[other] <= CARDINAL_FRESH) {
		*out = target == BAND_HIGH ? sig[other] - config.cardinal_delta
					   : sig[other] + config.cardinal_delta;
		*estimated = true;
		return true;
	}

	return false;
}

static void local_tick(void)
{
	enum roam_band target = cardinal_target();
	struct cardinal_entry *e, *tmp;
	struct roam_sta *sta;

	avl_for_each_element(&roam_sta_tree, sta, avl) {
		int sig[BAND_MAX], value;
		uint32_t age[BAND_MAX];
		uint64_t seen;
		enum roam_band b;
		bool estimated;

		if (!sta->bss || !roam_bss_matches(sta->bss) || manual_rule(sta->addr))
			continue;

		seen = sta->band[sta->bss->band].seen;
		e = entry_get(sta->addr, true);
		if (!e)
			continue;

		e->where = WHERE_LOCAL;
		e->gone = 0;
		e->touched = roam_now;

		if (seen == e->sample_seen)
			continue;
		e->sample_seen = seen;

		for (b = 0; b < BAND_MAX; b++) {
			const struct roam_sta_band *info = &sta->band[b];

			sig[b] = info->present ? info->signal : ROAMD_NO_SIGNAL;
			age[b] = info->present ? (uint32_t)(roam_now - info->seen) : UINT32_MAX;
		}

		if (sig[target] != ROAMD_NO_SIGNAL)
			e->ever_seen = true;

		if (sample_pick(sig, age, &value, &estimated))
			entry_sample(e, value, estimated);
	}

	avl_for_each_element_safe(&cardinal_tree, e, avl, tmp) {
		if (manual_rule(e->addr)) {
			entry_set(e, false, "manual rule");
			entry_free(e);
			continue;
		}

		if (e->where == WHERE_LOCAL) {
			sta = roam_sta_get(e->addr, false);
			if ((!sta || !sta->bss) && ++e->gone >= CARDINAL_GONE_TICKS) {
				if (mesh.enabled && mesh.role == MESH_CONTROLLER && e->blocked) {
					e->where = WHERE_REMOTE;
					e->poll_gen = cardinal_poll_gen - 1;
				} else {
					entry_set(e, false, "client left");
					e->where = WHERE_NONE;
				}
			}
		}

		if (!e->blocked && !e->pushed_until && roam_now - e->touched > CARDINAL_IDLE)
			entry_free(e);
	}
}

static void cardinal_clear(void)
{
	struct cardinal_entry *e, *tmp;

	avl_for_each_element_safe(&cardinal_tree, e, avl, tmp) {
		if (e->blocked)
			entry_set(e, false, "disabled");
		if (!e->pushed_until || e->pushed_until < roam_now)
			entry_free(e);
	}
}

static void cardinal_tick(struct uloop_timeout *t)
{
	roam_time_update();

	if (cardinal_decides())
		local_tick();
	else
		cardinal_clear();

	uloop_timeout_set(t, CARDINAL_TICK);
}

void cardinal_init(void)
{
	if (!cardinal_tree.comp)
		avl_init(&cardinal_tree, addr_cmp, false, NULL);

	cardinal_timer.cb = cardinal_tick;
	uloop_timeout_set(&cardinal_timer, CARDINAL_TICK);
}

enum roam_band cardinal_lock(const uint8_t *addr)
{
	struct cardinal_entry *e;

	if (!cardinal_tree.comp)
		return BAND_MAX;

	e = avl_find_element(&cardinal_tree, addr, e, avl);
	if (!e || e->band >= BAND_MAX)
		return BAND_MAX;

	if (e->blocked || (e->pushed_until && roam_now < e->pushed_until))
		return e->band;

	return BAND_MAX;
}

static void remote_sample(const uint8_t *addr, const char *mac, const char *node,
			  const int *sig, const uint32_t *sig_age, void *priv)
{
	struct cardinal_entry *e;
	struct roam_sta *sta;
	uint32_t age[BAND_MAX];
	enum roam_band b;
	bool estimated;
	int value;

	if (!strcmp(node, "controller") || manual_rule(addr))
		return;

	sta = roam_sta_get(addr, false);
	if (sta && sta->bss)
		return;

	e = entry_get(addr, true);
	if (!e)
		return;

	e->where = WHERE_REMOTE;
	e->poll_gen = cardinal_poll_gen;
	e->touched = roam_now;

	for (b = 0; b < BAND_MAX; b++)
		age[b] = sig[b] != ROAMD_NO_SIGNAL ? sig_age[b] * 1000 : UINT32_MAX;

	if (sig[cardinal_target()] != ROAMD_NO_SIGNAL)
		e->ever_seen = true;

	if (sample_pick(sig, age, &value, &estimated))
		entry_sample(e, value, estimated);
	else
		e->gone = 0;
}

void cardinal_poll_done(void)
{
	struct cardinal_entry *e;

	if (!cardinal_tree.comp || !cardinal_decides())
		return;

	roam_time_update();
	cardinal_poll_gen++;
	mesh_clients_each(remote_sample, NULL);

	avl_for_each_element(&cardinal_tree, e, avl)
		if (e->where == WHERE_REMOTE && e->poll_gen != cardinal_poll_gen) {
			entry_set(e, false, "client left");
			e->where = WHERE_NONE;
		}
}

char *cardinal_locks_json(void)
{
	static struct blob_buf b;
	struct cardinal_entry *e;
	void *arr;

	blob_buf_init(&b, 0);
	arr = blobmsg_open_array(&b, "locks");

	if (cardinal_tree.comp)
		avl_for_each_element(&cardinal_tree, e, avl) {
			void *t;

			if (!e->blocked)
				continue;

			t = blobmsg_open_table(&b, NULL);
			blobmsg_add_string(&b, "mac", e->mac);
			blobmsg_add_string(&b, "band", roam_band_name(e->band));
			blobmsg_close_table(&b, t);
		}

	blobmsg_close_array(&b, arr);

	return blobmsg_format_json(b.head, true);
}

void cardinal_set_remote(struct blob_attr *locks)
{
	static const struct blobmsg_policy lp[2] = {
		{ "mac", BLOBMSG_TYPE_STRING },
		{ "band", BLOBMSG_TYPE_STRING },
	};
	struct cardinal_entry *e, *tmp;
	struct blob_attr *cur;
	int rem;

	if (!cardinal_tree.comp)
		avl_init(&cardinal_tree, addr_cmp, false, NULL);

	roam_time_update();

	avl_for_each_element_safe(&cardinal_tree, e, avl, tmp)
		if (!e->blocked)
			entry_free(e);

	if (!locks)
		return;

	blobmsg_for_each_attr(cur, locks, rem) {
		struct blob_attr *tb[2];
		struct ether_addr ea;
		const char *band;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_parse(lp, 2, tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[0] || !tb[1] || !ether_aton_r(blobmsg_get_string(tb[0]), &ea))
			continue;

		band = blobmsg_get_string(tb[1]);
		if (strcmp(band, "5") && strcmp(band, "2.4"))
			continue;

		e = entry_get(ea.ether_addr_octet, true);
		if (!e)
			continue;

		e->band = band[0] == '5' ? BAND_HIGH : BAND_LOW;
		e->pushed_until = roam_now + CARDINAL_REMOTE_TTL;
	}
}

void cardinal_dump(struct blob_buf *b)
{
	static const char *const where_name[] = { "none", "local", "remote" };
	struct cardinal_entry *e;
	void *arr;

	blobmsg_add_u8(b, "enabled", cardinal_decides());
	blobmsg_add_u32(b, "window", config.cardinal_window);
	blobmsg_add_u32(b, "error_max", config.cardinal_error_max);
	blobmsg_add_u32(b, "delta", (uint32_t)config.cardinal_delta);

	arr = blobmsg_open_array(b, "clients");

	if (cardinal_tree.comp)
		avl_for_each_element(&cardinal_tree, e, avl) {
			void *t = blobmsg_open_table(b, NULL);

			blobmsg_add_string(b, "mac", e->mac);
			blobmsg_add_string(b, "where", where_name[e->where]);
			blobmsg_add_u8(b, "blocked", e->blocked);
			if (e->band < BAND_MAX)
				blobmsg_add_string(b, "band", roam_band_name(e->band));
			if (e->pushed_until > roam_now)
				blobmsg_add_u32(b, "pushed_ttl",
						(uint32_t)((e->pushed_until - roam_now) / 1000));
			blobmsg_add_u8(b, "ever_seen", e->ever_seen);
			if (e->last_sample) {
				blobmsg_add_u32(b, "signal", (uint32_t)e->last_signal);
				blobmsg_add_u8(b, "estimated", e->estimated);
				blobmsg_add_u32(b, "sample_age",
						(uint32_t)((roam_now - e->last_sample) / 1000));
			}
			blobmsg_add_u32(b, "stable", (uint32_t)((roam_now - e->stable_since) / 1000));
			blobmsg_add_u32(b, "errors", e->error_count);
			blobmsg_close_table(b, t);
		}

	blobmsg_close_array(b, arr);
}
