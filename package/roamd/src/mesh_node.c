#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#include <libubox/uloop.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_WATCH_INTERVAL	5000
#define MESH_CONTACT_MISS	15000
#define MESH_SEG_TICK		30000
#define MESH_DROP_REASON	4
#define MESH_RESOLV		"/tmp/resolv.conf"
#define MESH_RESOLV_AUTO	"/tmp/resolv.conf.d/resolv.conf.auto"

static struct uloop_timeout watch_timer;
static uint64_t last_contact;
static bool aps_down;
static bool aps_state_known;

/* what "/etc/init.d/<name> enabled" checks: a start link in /etc/rc.d */
static bool service_enabled(const char *name)
{
	DIR *d = opendir("/etc/rc.d");
	struct dirent *de;
	bool found = false;

	if (!d)
		return false;

	while (!found && (de = readdir(d)))
		found = de->d_name[0] == 'S' && strlen(de->d_name) > 3 &&
			isdigit((unsigned char)de->d_name[1]) &&
			isdigit((unsigned char)de->d_name[2]) &&
			!strcmp(de->d_name + 3, name);

	closedir(d);

	return found;
}

static bool process_running(const char *name)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	bool found = false;

	if (!d)
		return false;

	while (!found && (de = readdir(d))) {
		char path[300], comm[32] = "";
		FILE *f;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "/proc/%s/comm", de->d_name);
		f = fopen(path, "r");
		if (!f)
			continue;

		if (fgets(comm, sizeof(comm), f))
			comm[strcspn(comm, "\n")] = '\0';
		fclose(f);

		found = !strcmp(comm, name);
	}

	closedir(d);

	return found;
}

static bool service_off(const char *name)
{
	char cmd[96];
	bool changed = false;

	if (service_enabled(name)) {
		snprintf(cmd, sizeof(cmd), "/etc/init.d/%s disable >/dev/null 2>&1", name);
		changed = !system(cmd);
		roam_stats.forks++;
	}

	if (process_running(name)) {
		snprintf(cmd, sizeof(cmd), "/etc/init.d/%s stop >/dev/null 2>&1", name);
		changed = !system(cmd) || changed;
		roam_stats.forks++;
	}

	return changed;
}

/*
 * The controller reaches the node over https only. Some firmware (ImmortalWrt)
 * ships uhttpd without listen_https, so the certificate set at capture is
 * never served; add the listeners if they are missing.
 */
static void node_https(void)
{
	struct uci_session u;
	struct uci_section *s;
	const char *cert;
	bool changed;

	if (!uci_session_open(&u, "uhttpd"))
		return;

	s = uci_lookup_section(u.ctx, u.pkg, "main");
	cert = s ? uci_lookup_option_string(u.ctx, s, "cert") : NULL;
	if (cert && !strcmp(cert, "/etc/roamd-node.crt") && !uci_lookup_option(u.ctx, s, "listen_https")) {
		uci_session_add_list(&u, "main", "listen_https", "0.0.0.0:443");
		uci_session_add_list(&u, "main", "listen_https", "[::]:443");
	}

	changed = u.dirty;
	uci_session_close(&u);

	if (changed) {
		roam_log(ROAM_L_INFO, "mesh: uhttpd had no https listener, enabled port 443");
		if (system("/etc/init.d/uhttpd restart >/dev/null 2>&1"))
			roam_log(ROAM_L_INFO, "mesh: uhttpd restart failed");
	}
}

void mesh_node_dumbap(void)
{
	static const char *const services[] = { "dnsmasq", "odhcpd" };
	static const struct {
		const char *section;
		const char *option;
		const char *value;
	} wanted[] = {
		{ "lan", "ignore", "1" },
		{ "lan", "dhcpv4", "disabled" },
		{ "lan", "dhcpv6", "disabled" },
		{ "lan", "ra", "disabled" },
	};
	char link[64];
	struct uci_session u;
	struct uci_section *dns;
	bool changed = false;
	size_t i;

	if (mesh.role != MESH_NODE)
		return;

	node_https();

	if (uci_session_open(&u, "dhcp")) {
		for (i = 0; i < ARRAY_SIZE(wanted); i++)
			uci_session_set(&u, wanted[i].section, wanted[i].option, wanted[i].value);

		dns = uci_session_find(&u, "dnsmasq", NULL, NULL);
		if (dns) {
			uci_session_set(&u, dns->e.name, "noresolv", "1");

			if (mesh.controller_addr[0]) {
				struct uci_option *o = uci_lookup_option(u.ctx, dns, "server");
				const char *first = o && o->type == UCI_TYPE_LIST &&
						    o->v.list.next != &o->v.list ?
						    list_to_element(o->v.list.next)->name : NULL;

				if (!first || strcmp(first, mesh.controller_addr)) {
					uci_session_delete(&u, dns->e.name, "server");
					uci_session_add_list(&u, dns->e.name, "server",
							     mesh.controller_addr);
				}
			}
		}

		changed = u.dirty;
		uci_session_close(&u);
	}

	if (readlink(MESH_RESOLV, link, sizeof(link) - 1) <= 0 ||
	    strncmp(link, MESH_RESOLV_AUTO, strlen(MESH_RESOLV_AUTO))) {
		unlink(MESH_RESOLV);
		changed = !symlink(MESH_RESOLV_AUTO, MESH_RESOLV) || changed;
	}

	for (i = 0; i < ARRAY_SIZE(services); i++)
		changed = service_off(services[i]) || changed;

	if (changed)
		roam_log(ROAM_L_INFO, "mesh: dumb AP enforced");
}

void mesh_node_touch(void)
{
	last_contact = roam_now;
}

bool mesh_node_contact_lost(void)
{
	return roam_now - last_contact > MESH_CONTACT_MISS;
}

static bool contact_was_lost;

static bool client_ap(struct uci_context *ctx, struct uci_section *s)
{
	const char *mode = uci_lookup_option_string(ctx, s, "mode");

	return mode && !strcmp(mode, "ap") &&
	       strncmp(s->e.name, MESH_BH_PREFIX, strlen(MESH_BH_PREFIX));
}

static void aps_set_disabled(bool disabled)
{
	struct uci_session u;
	struct uci_element *e;

	if (!uci_session_open(&u, "wireless"))
		return;

	uci_foreach_element(&u.pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!client_ap(u.ctx, s))
			continue;

		uci_session_set(&u, s->e.name, "disabled", disabled ? "1" : "0");
	}

	if (u.dirty) {
		uci_session_close(&u);
		roam_network_reload(disabled ? "access points off, no path to the controller" :
				    "access points back on");

		return;
	}

	uci_session_close(&u);
}

static void aps_ensure(bool up)
{
	if (aps_state_known && aps_down == !up)
		return;

	aps_set_disabled(!up);
	aps_down = !up;
	aps_state_known = true;

	roam_log(ROAM_L_INFO, "mesh: node access points %s", up ? "restored" : "shut down");
}

bool mesh_cmd_line(const char *cmd, char *buf, size_t len)
{
	FILE *f = popen(cmd, "r");
	char line[128];
	bool got = false;

	buf[0] = '\0';
	if (!f)
		return false;

	roam_stats.forks++;

	if (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = '\0';
		strncpy(buf, line, len - 1);
		buf[len - 1] = '\0';
		got = buf[0] != '\0';
	}

	pclose(f);
	return got;
}

static struct uloop_fd probe = { .fd = -1 };
static struct in_addr probe_addr;
static uint16_t probe_seq;

bool mesh_icmp_ping(const char *addr, int timeout_ms)
{
	struct sockaddr_in to = { .sin_family = AF_INET };
	struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
	struct icmphdr ic = { .type = ICMP_ECHO, .un.echo.id = htons(MESH_PROBE_ID) };
	uint8_t buf[256];
	bool ok = false;
	int fd;

	if (!inet_pton(AF_INET, addr, &to.sin_addr))
		return false;

	fd = mesh_icmp_socket(AF_INET);
	if (fd < 0)
		return false;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	ic.checksum = mesh_icmp_sum(&ic, sizeof(ic));

	if (sendto(fd, &ic, sizeof(ic), 0, (struct sockaddr *)&to, sizeof(to)) == sizeof(ic))
		ok = recv(fd, buf, sizeof(buf), 0) > 0;

	close(fd);

	return ok;
}

static void probe_reply_cb(struct uloop_fd *u, unsigned int events)
{
	uint8_t buf[128];
	struct sockaddr_in from;
	socklen_t len = sizeof(from);
	ssize_t n;

	while ((n = recvfrom(u->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &len)) > 0) {
		const struct iphdr *ip = (const struct iphdr *)buf;
		const struct icmphdr *ic;
		size_t hl = ip->ihl * 4;

		len = sizeof(from);
		if ((size_t)n < hl + sizeof(*ic) || from.sin_addr.s_addr != probe_addr.s_addr)
			continue;

		ic = (const struct icmphdr *)(buf + hl);
		if (ic->type == ICMP_ECHOREPLY && ic->un.echo.id == htons(MESH_PROBE_ID)) {
			roam_time_update();
			mesh_node_touch();
		}
	}
}

static void probe_send(void)
{
	struct sockaddr_in sa = { .sin_family = AF_INET };
	struct icmphdr ic = { .type = ICMP_ECHO };

	if (inet_pton(AF_INET, mesh.controller_addr, &sa.sin_addr) != 1)
		return;

	if (probe.fd < 0) {
		probe.fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
		if (probe.fd < 0)
			return;

		probe.cb = probe_reply_cb;
		uloop_fd_add(&probe, ULOOP_READ);
	}

	probe_addr = sa.sin_addr;
	ic.un.echo.id = htons(MESH_PROBE_ID);
	ic.un.echo.sequence = htons(++probe_seq);
	ic.checksum = mesh_icmp_sum(&ic, sizeof(ic));
	sendto(probe.fd, &ic, sizeof(ic), 0, (struct sockaddr *)&sa, sizeof(sa));
}

static void seg_watch(void)
{
	static uint64_t next;

	if (roam_now < next)
		return;

	next = roam_now + MESH_SEG_TICK;

	if (mesh_seg_node_apply())
		roam_network_reload("segments");

	mesh_seg_links_sync();
}

static void node_watch(void)
{
	bool alive, relay;


	mesh_bridge_wifi_cost();
	seg_watch();

	probe_send();

	alive = mesh_bh_link_check();


	if (mesh_node_contact_lost() != contact_was_lost) {
		contact_was_lost = !contact_was_lost;
		if (contact_was_lost) {
			roam_stats.contact_losses++;
			roam_log(ROAM_L_ERR, "mesh: no contact with the controller for %u s",
				 mesh_node_contact_age());
		} else {
			roam_log(ROAM_L_INFO, "mesh: contact with the controller is back");
		}
	}

	relay = mesh_bh_step(alive);
	mesh_node_led_set(!mesh_node_contact_lost());
	mesh_bh_relay(relay);

	if (mesh.wifi_shutdown)
		aps_ensure(relay);
	else if (aps_state_known && aps_down)
		aps_ensure(true);
}

static void watch_cb(struct uloop_timeout *t)
{
	roam_time_update();

	if (mesh.role == MESH_NODE)
		node_watch();
	else {
		last_contact = 0;
		contact_was_lost = false;
		if (aps_state_known && aps_down)
			aps_ensure(true);
	}

	uloop_timeout_set(&watch_timer, MESH_WATCH_INTERVAL);
}

uint64_t mesh_node_last_contact(void)
{
	return last_contact;
}

uint32_t mesh_node_contact_age(void)
{
	if (!last_contact || roam_now < last_contact)
		return 0;

	return (uint32_t)((roam_now - last_contact) / 1000);
}

void mesh_node_watch_start(void)
{
	/* a config reload keeps the contact time and the backhaul it already tracks */
	if (!last_contact) {
		last_contact = roam_now;
		mesh_bh_restore();
	}

	if (watch_timer.cb)
		return;

	watch_timer.cb = watch_cb;
	uloop_timeout_set(&watch_timer, MESH_WATCH_INTERVAL);
}

bool mesh_node_apply(struct blob_attr *msg)
{
	if (!mesh_node_profile_write(msg))
		return false;

	mesh_bh_limit_enforce();
	roam_wireless_apply();
	roam_bss_recheck();
	mesh_bh_profile_applied();

	return true;
}

void mesh_node_watch_blob(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "watchdog");

	blobmsg_add_u32(b, "contact_age", mesh_node_contact_age());
	blobmsg_add_u8(b, "contact_lost", mesh_node_contact_lost());
	mesh_bh_blob(b);
	blobmsg_add_u8(b, "aps_down", aps_down);
	blobmsg_add_string(b, "uplink_port", mesh_bh_uplink_port());
	blobmsg_add_u32(b, "contact_losses", roam_stats.contact_losses);
	blobmsg_close_table(b, t);
}

bool mesh_node_steer(const char *macstr, const char *node, struct blob_attr *neighbors,
		     const char **reason)
{
	static struct blob_buf sb;
	struct ether_addr *ea = ether_aton(macstr);
	struct roam_sta *sta;
	int signal;

	*reason = "not connected here";

	if (!ea)
		return false;

	sta = roam_sta_get(ea->ether_addr_octet, false);
	if (!sta || !sta->bss)
		return false;

	signal = sta->band[sta->bss->band].signal;

	if (!roam_policy_can_steer(sta)) {
		*reason = roam_policy_btm_paused(sta->addr) ? "client keeps refusing, paused" :
			  sta->steer_count >= config.steer_retries ?
			  "steer attempts used up" : "steered moments ago";
		return false;
	}

	if (!sta->btm) {
		if (!config.allow_kick) {
			*reason = "no 802.11v, disconnecting is off";
			return false;
		}

		roam_log(ROAM_L_INFO,
			 "mesh: controller moves %s to %s, no 802.11v — disconnecting",
			 sta->mac, node ? node : "another device");
		roam_policy_kick(sta, sta->bss);

		return true;
	}

	blob_buf_init(&sb, 0);
	blobmsg_add_string(&sb, "addr", sta->mac);
	blobmsg_add_u32(&sb, "dialog_token", roam_policy_btm_token(sta));
	blobmsg_add_u8(&sb, "disassociation_imminent", 0);
	blobmsg_add_u32(&sb, "disassociation_timer", 0);
	blobmsg_add_u32(&sb, "reassoc_delay", 0);
	blobmsg_add_u32(&sb, "mbo_reason", roam_policy_mbo_reason(signal));
	blobmsg_add_u32(&sb, "cell_pref", 0);
	blobmsg_add_u8(&sb, "abridged", 1);

	if (neighbors) {
		struct blob_attr *cur;
		void *arr;
		int rem;

		arr = blobmsg_open_array(&sb, "neighbors");
		blobmsg_for_each_attr(cur, neighbors, rem)
			if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
				blobmsg_add_string(&sb, NULL, blobmsg_get_string(cur));
		blobmsg_close_array(&sb, arr);
	}

	roam_bss_invoke(sta->bss, "bss_transition_request", &sb);

	sta->last_steer = roam_now;
	sta->steer_from = sta->bss->band;
	sta->steer_count++;

	mesh_log_local(sta->mac, sta->bss->band, MESH_BAND_NA, node, MESH_EV_STEER);

	roam_log(ROAM_L_INFO,
		 "mesh: controller asks %s to move to %s at %d dBm (attempt %u of %u)",
		 sta->mac, node ? node : "another access point", signal,
		 sta->steer_count, config.steer_retries);

	return true;
}

bool mesh_node_drop(const char *macstr)
{
	static struct blob_buf db;
	struct ether_addr *ea = ether_aton(macstr);
	struct roam_sta *sta;

	if (!ea)
		return false;

	sta = roam_sta_get(ea->ether_addr_octet, false);
	if (!sta || !sta->bss)
		return false;

	blob_buf_init(&db, 0);
	blobmsg_add_string(&db, "addr", sta->mac);
	blobmsg_add_u32(&db, "reason", MESH_DROP_REASON);
	blobmsg_add_u8(&db, "deauth", 1);
	roam_bss_invoke(sta->bss, "del_client", &db);

	roam_log(ROAM_L_INFO, "mesh: %s is associated elsewhere, removed from %s",
		 sta->mac, sta->bss->ifname);
	roam_sta_disconnected(sta);

	return true;
}
