#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_UI_PORTS		"80 443"
#define MESH_UI_ALLOW_IP	"roamd_ui_ctrl_ip"
#define MESH_UI_ALLOW_MAC	"roamd_ui_ctrl_mac"
#define MESH_UI_BLOCK		"roamd_ui_block"

static bool opt_allowed(const char *const *allowed, const char *name)
{
	for (; *allowed; allowed++)
		if (!strcmp(*allowed, name))
			return true;

	return false;
}

static bool opt_value_safe(const char *v)
{
	for (; *v; v++)
		if (*v == '\n' || *v == '\r')
			return false;

	return true;
}

static void apply_table(struct uci_session *u, const char *section, struct blob_attr *table,
			const char *const *allowed)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return;

	blobmsg_for_each_attr(cur, table, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!opt_allowed(allowed, blobmsg_name(cur)) ||
		    !opt_value_safe(blobmsg_get_string(cur))) {
			roam_log(ROAM_L_ERR, "mesh: profile option %s.%s rejected",
				 section, blobmsg_name(cur));
			continue;
		}

		uci_session_set(u, section, blobmsg_name(cur), blobmsg_get_string(cur));
	}
}

enum {
	APPLY_CONTROLLER_ID,
	APPLY_GLOBAL,
	APPLY_POLICY,
	APPLY_BACKHAUL,
	APPLY_DEVICES,
	APPLY_NETWORKS,
	APPLY_SYSTEM,
	APPLY_CREDS,
	APPLY_TXPOWER,
	APPLY_COUNTRY,
	__APPLY_MAX
};

static const struct blobmsg_policy apply_policy[__APPLY_MAX] = {
	[APPLY_CONTROLLER_ID] = { .name = "controller_id", .type = BLOBMSG_TYPE_STRING },
	[APPLY_GLOBAL] = { .name = "global", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_POLICY] = { .name = "policy", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_BACKHAUL] = { .name = "backhaul", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_DEVICES] = { .name = "devices", .type = BLOBMSG_TYPE_ARRAY },
	[APPLY_NETWORKS] = { .name = "networks", .type = BLOBMSG_TYPE_ARRAY },
	[APPLY_SYSTEM] = { .name = "system", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_CREDS] = { .name = "credentials", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_TXPOWER] = { .name = "txpower", .type = BLOBMSG_TYPE_TABLE },
	[APPLY_COUNTRY] = { .name = "country", .type = BLOBMSG_TYPE_STRING },
};

enum { TXP_24, TXP_5, TXP_CH24, TXP_CH5, TXP_W24, TXP_W5, __TXP_MAX };

static const struct blobmsg_policy txpower_policy[__TXP_MAX] = {
	[TXP_24] = { .name = "txpower_24", .type = BLOBMSG_TYPE_INT32 },
	[TXP_5] = { .name = "txpower_5", .type = BLOBMSG_TYPE_INT32 },
	[TXP_CH24] = { .name = "channel_24", .type = BLOBMSG_TYPE_INT32 },
	[TXP_CH5] = { .name = "channel_5", .type = BLOBMSG_TYPE_INT32 },
	[TXP_W24] = { .name = "width_24", .type = BLOBMSG_TYPE_INT32 },
	[TXP_W5] = { .name = "width_5", .type = BLOBMSG_TYPE_INT32 },
};


/*
 * The profile is the same for every node; pick our own entry. Values applied
 * earlier are remembered in roamd.mesh so that a later 0 can clear them. The
 * channel of a band that carries our wireless uplink is set by the parent.
 */
static bool apply_txpower(struct uci_session *u, struct blob_attr *table)
{
	struct blob_attr *mine = NULL, *cur, *tb[__TXP_MAX];
	int tx[BAND_MAX] = { 0, 0 }, ch[BAND_MAX] = { 0, 0 }, w[BAND_MAX] = { 0, 0 };
	int prev_tx[BAND_MAX], prev_ch[BAND_MAX];
	const char *uplink;
	uint8_t keep = 0;
	char value[12];
	unsigned int k;
	bool changed;
	int rem;

	if (!table || !mesh.member_id[0])
		return false;

	blobmsg_for_each_attr(cur, table, rem)
		if (blobmsg_type(cur) == BLOBMSG_TYPE_TABLE && !strcmp(blobmsg_name(cur), mesh.member_id))
			mine = cur;

	if (!mine)
		return false;

	blobmsg_parse(txpower_policy, __TXP_MAX, tb, blobmsg_data(mine), blobmsg_data_len(mine));

	for (k = 0; k < __MESH_RADIO_MAX; k++) {
		int *slot = mesh_radio_slot(tx, ch, w, k);

		if (tb[k])
			*slot = (int)blobmsg_get_u32(tb[k]);
		if (!mesh_radio_value_ok(k, *slot))
			*slot = 0;
	}

	memcpy(prev_tx, mesh.txpower, sizeof(prev_tx));
	memcpy(prev_ch, mesh.channel, sizeof(prev_ch));

	for (k = 0; k < __MESH_RADIO_MAX; k++) {
		snprintf(value, sizeof(value), "%d", *mesh_radio_slot(tx, ch, w, k));
		uci_session_set(u, "mesh", mesh_radio_opts[k], value);
	}

	uplink = mesh_node_uplink_band();
	if (!strcmp(uplink, "2.4"))
		keep = MESH_BAND_24;
	else if (!strcmp(uplink, "5"))
		keep = MESH_BAND_5;

	changed = mesh_txpower_apply(tx, prev_tx);

	return mesh_channel_apply(ch, w, prev_ch, keep) || changed;
}

/* The region is the same for the whole system; roamd.mesh.country remembers what we wrote. */
static bool apply_country(struct uci_session *u, struct blob_attr *attr)
{
	const char *want;

	if (!attr)
		return false;

	want = blobmsg_get_string(attr);
	if (!mesh_country_valid(want)) {
		roam_log(ROAM_L_ERR, "mesh: profile region rejected");
		return false;
	}

	if (want[0])
		uci_session_set(u, "mesh", "country", want);
	else
		uci_session_delete(u, "mesh", "country");

	/* An empty region (controllers before 1.3.5) leaves the radios as they are. */
	return mesh_country_apply(want, NULL);
}

enum { SYS_TIMEZONE, SYS_ZONENAME, __SYS_MAX };

static const struct blobmsg_policy system_policy[__SYS_MAX] = {
	[SYS_TIMEZONE] = { .name = "timezone", .type = BLOBMSG_TYPE_STRING },
	[SYS_ZONENAME] = { .name = "zonename", .type = BLOBMSG_TYPE_STRING },
};

static void apply_system(struct blob_attr *sys)
{
	static const char *const names[] = { "timezone", "zonename" };
	struct blob_attr *tb[__SYS_MAX];
	struct uci_session u;
	struct uci_section *sec;
	size_t i;

	if (!sys)
		return;

	blobmsg_parse(system_policy, __SYS_MAX, tb, blobmsg_data(sys), blobmsg_data_len(sys));

	if (!uci_session_open(&u, "system"))
		return;

	sec = uci_session_find(&u, "system", NULL, NULL);

	for (i = 0; sec && i < ARRAY_SIZE(names); i++) {
		const char *cur = uci_lookup_option_string(u.ctx, sec, names[i]);
		const char *want;

		if (!tb[i])
			continue;

		want = blobmsg_get_string(tb[i]);
		if (cur && !strcmp(cur, want))
			continue;

		uci_session_set(&u, sec->e.name, names[i], want);
	}

	if (u.dirty) {
		uci_session_close(&u);

		if (system("/etc/init.d/system reload >/dev/null 2>&1"))
			roam_log(ROAM_L_ERR, "mesh: time zone written, reload failed");
		else
			roam_log(ROAM_L_INFO, "mesh: time zone updated from the controller");

		return;
	}

	uci_session_close(&u);
}


enum { DEV_MAC, DEV_BAND, DEV_NODES, __DEV_MAX };

static const struct blobmsg_policy dev_policy[__DEV_MAX] = {
	[DEV_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
	[DEV_BAND] = { .name = "band", .type = BLOBMSG_TYPE_STRING },
	[DEV_NODES] = { .name = "nodes", .type = BLOBMSG_TYPE_ARRAY },
};

static bool device_same(struct uci_session *u, struct uci_section *s, struct blob_attr **tb)
{
	const char *mac = uci_lookup_option_string(u->ctx, s, "mac");
	const char *band = uci_lookup_option_string(u->ctx, s, "band");
	struct uci_option *o = uci_lookup_option(u->ctx, s, "node");
	const char *want[MESH_ALLOW_MAX];
	unsigned int n_want = 0, i = 0;
	struct uci_element *e;
	struct blob_attr *n;
	int nrem;

	if (!mac || strcmp(mac, blobmsg_get_string(tb[DEV_MAC])))
		return false;

	if (!band != !tb[DEV_BAND] || (band && strcmp(band, blobmsg_get_string(tb[DEV_BAND]))))
		return false;

	if (o && o->type != UCI_TYPE_LIST)
		return false;

	if (tb[DEV_NODES])
		blobmsg_for_each_attr(n, tb[DEV_NODES], nrem) {
			if (blobmsg_type(n) != BLOBMSG_TYPE_STRING)
				continue;
			if (n_want >= ARRAY_SIZE(want))
				return false;
			want[n_want++] = blobmsg_get_string(n);
		}

	if (o)
		uci_foreach_element(&o->v.list, e) {
			if (i >= n_want || strcmp(e->name, want[i]))
				return false;
			i++;
		}

	return i == n_want;
}

static bool devices_same(struct uci_session *u, struct blob_attr *devices)
{
	struct uci_section *have[256];
	unsigned int n_have = 0, n_want = 0;
	struct uci_element *e;
	struct blob_attr *cur;
	int rem;

	uci_foreach_element(&u->pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "device"))
			continue;

		if (n_have >= ARRAY_SIZE(have))
			return false;

		have[n_have++] = s;
	}

	if (devices) {
		blobmsg_for_each_attr(cur, devices, rem) {
			struct blob_attr *tb[__DEV_MAX];

			if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
				continue;

			blobmsg_parse(dev_policy, __DEV_MAX, tb,
				      blobmsg_data(cur), blobmsg_data_len(cur));
			if (!tb[DEV_MAC])
				continue;

			if (n_want >= n_have || !device_same(u, have[n_want], tb))
				return false;

			n_want++;
		}
	}

	return n_want == n_have;
}

static void apply_devices(struct uci_session *u, struct blob_attr *devices)
{
	struct uci_element *e, *tmp;
	struct blob_attr *cur;
	int rem;

	if (devices_same(u, devices))
		return;

	uci_foreach_element_safe(&u->pkg->sections, tmp, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "device"))
			uci_session_delete(u, s->e.name, NULL);
	}

	if (!devices)
		return;

	blobmsg_for_each_attr(cur, devices, rem) {
		struct blob_attr *tb[__DEV_MAX];
		struct uci_section *ns;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_parse(dev_policy, __DEV_MAX, tb,
			      blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[DEV_MAC])
			continue;

		ns = uci_session_add(u, "device", NULL);
		if (!ns)
			continue;

		uci_session_set(u, ns->e.name, "mac", blobmsg_get_string(tb[DEV_MAC]));

		if (tb[DEV_BAND])
			uci_session_set(u, ns->e.name, "band", blobmsg_get_string(tb[DEV_BAND]));

		if (tb[DEV_NODES]) {
			struct blob_attr *n;
			int nrem;

			blobmsg_for_each_attr(n, tb[DEV_NODES], nrem)
				if (blobmsg_type(n) == BLOBMSG_TYPE_STRING)
					uci_session_add_list(u, ns->e.name, "node", blobmsg_get_string(n));
		}
	}
}

static void ui_rule(struct uci_session *u, const char *name, const char *key,
		    const char *value)
{
	if (!uci_session_add(u, "rule", name))
		return;

	uci_session_set(u, name, "name", name);
	uci_session_set(u, name, "src", "*");
	uci_session_set(u, name, "proto", "tcp");
	uci_session_set(u, name, "dest_port", MESH_UI_PORTS);
	uci_session_set(u, name, "target", key ? "ACCEPT" : "DROP");

	if (key)
		uci_session_set(u, name, key, value);
}

static bool ui_rule_same(struct uci_session *u, const char *name, const char *key,
			 const char *value)
{
	struct uci_section *s = uci_lookup_section(u->ctx, u->pkg, name);
	const char *want[][2] = {
		{ "name", name }, { "src", "*" }, { "proto", "tcp" },
		{ "dest_port", MESH_UI_PORTS }, { "target", key ? "ACCEPT" : "DROP" },
		{ key, value },
	};
	size_t i;

	if (!s || strcmp(s->type, "rule"))
		return false;

	for (i = 0; i < ARRAY_SIZE(want); i++) {
		const char *have;

		if (!want[i][0])
			continue;

		have = uci_lookup_option_string(u->ctx, s, want[i][0]);
		if (!have || strcmp(have, want[i][1]))
			return false;
	}

	return true;
}

/* the rules node_ui_guard would write are already there, and nothing else of ours */
static bool ui_rules_same(struct uci_session *u, bool open)
{
	bool ip = !open && mesh.controller_addr[0];
	bool mac = !open && mesh.controller_mac[0];

	if (ip != !!uci_lookup_section(u->ctx, u->pkg, MESH_UI_ALLOW_IP) ||
	    mac != !!uci_lookup_section(u->ctx, u->pkg, MESH_UI_ALLOW_MAC) ||
	    open == !!uci_lookup_section(u->ctx, u->pkg, MESH_UI_BLOCK))
		return false;

	if (open)
		return true;

	return (!ip || ui_rule_same(u, MESH_UI_ALLOW_IP, "src_ip", mesh.controller_addr)) &&
	       (!mac || ui_rule_same(u, MESH_UI_ALLOW_MAC, "src_mac", mesh.controller_mac)) &&
	       ui_rule_same(u, MESH_UI_BLOCK, NULL, NULL);
}

static void node_ui_guard(void)
{
	static int applied = -1;
	int want = mesh.node_ui ? 1 : 0;
	struct uci_session u;

	if (applied == want)
		return;

	if (!uci_session_open(&u, "firewall"))
		return;

	if (ui_rules_same(&u, want)) {
		uci_session_close(&u);
		applied = want;
		return;
	}

	uci_session_delete(&u, MESH_UI_ALLOW_IP, NULL);
	uci_session_delete(&u, MESH_UI_ALLOW_MAC, NULL);
	uci_session_delete(&u, MESH_UI_BLOCK, NULL);

	if (!want) {
		if (mesh.controller_addr[0])
			ui_rule(&u, MESH_UI_ALLOW_IP, "src_ip", mesh.controller_addr);

		if (mesh.controller_mac[0])
			ui_rule(&u, MESH_UI_ALLOW_MAC, "src_mac", mesh.controller_mac);

		ui_rule(&u, MESH_UI_BLOCK, NULL, NULL);
	}

	uci_session_close(&u);
	applied = want;

	if (system("/etc/init.d/firewall reload >/dev/null 2>&1"))
		roam_log(ROAM_L_ERR, "mesh: web interface rules written, firewall reload failed");
	else
		roam_log(ROAM_L_INFO, "mesh: node web interface %s",
			 want ? "open" : "closed for everyone but the controller");
}

bool mesh_node_profile_write(struct blob_attr *msg)
{
	struct blob_attr *tb[__APPLY_MAX];
	struct uci_session u;
	const char *from;
	bool txpower_changed, country_changed;

	blobmsg_parse(apply_policy, __APPLY_MAX, tb, blob_data(msg), blob_len(msg));

	if (!tb[APPLY_CONTROLLER_ID])
		return false;

	from = blobmsg_get_string(tb[APPLY_CONTROLLER_ID]);
	if (!mesh.controller_id[0] || strcmp(from, mesh.controller_id)) {
		roam_log(ROAM_L_ERR, "mesh: profile from an unknown controller rejected");
		return false;
	}

	if (!uci_session_open(&u, "roamd"))
		return false;

	apply_table(&u, "global", tb[APPLY_GLOBAL], mesh_global_opts);
	if (tb[APPLY_GLOBAL] &&
	    !mesh_attr_field(tb[APPLY_GLOBAL], "max_inactivity", BLOBMSG_TYPE_STRING))
		uci_session_delete(&u, "global", "max_inactivity");
	apply_table(&u, "policy", tb[APPLY_POLICY], mesh_policy_opts);
	apply_table(&u, "mesh", tb[APPLY_BACKHAUL], mesh_backhaul_opts);
	apply_devices(&u, tb[APPLY_DEVICES]);
	txpower_changed = apply_txpower(&u, tb[APPLY_TXPOWER]);
	country_changed = apply_country(&u, tb[APPLY_COUNTRY]);

	uci_session_close(&u);

	if (mesh_networks_apply(tb[APPLY_NETWORKS]) || txpower_changed || country_changed)
		roam_network_reload("profile from the controller");

	apply_system(tb[APPLY_SYSTEM]);
	mesh_node_creds_apply(tb[APPLY_CREDS]);
	mesh_node_dumbap();

	mesh_node_touch();
	roam_config_load();
	node_ui_guard();

	return true;
}
