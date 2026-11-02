#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libubox/uloop.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_FT_WATCH_INTERVAL	60000
#define MESH_WPAD_INIT		"/etc/init.d/wpad"
#define MESH_RRB_PROTO		"88b7"

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

void mesh_members_clear(void)
{
	struct mesh_member *m, *tmp;

	list_for_each_entry_safe(m, tmp, &mesh_members, list) {
		list_del(&m->list);
		free(m);
	}
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
