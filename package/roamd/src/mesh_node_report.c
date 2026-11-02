#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>

#include "roamd.h"
#include "mesh.h"

static void node_profile(struct blob_buf *b)
{
	void *t = blobmsg_open_table(b, "profile");

	blobmsg_add_string(b, "networks_sum", mesh.networks_sum);
	mesh_networks_dump(b, "networks", false);

	if (mesh.backhaul_ssid[0])
		blobmsg_add_string(b, "backhaul_ssid", mesh.backhaul_ssid);

	blobmsg_close_table(b, t);
}




static void release_field(const char *key, char *dst, size_t size)
{
	FILE *f = fopen("/etc/openwrt_release", "r");
	char line[128];

	dst[0] = '\0';
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		char *v = strstr(line, key);

		if (v) {
			v += strlen(key);
			while (*v == '\'' || *v == '"')
				v++;
			strncpy(dst, v, size - 1);
			dst[size - 1] = '\0';
			dst[strcspn(dst, "'\"\r\n")] = '\0';
			break;
		}
	}

	fclose(f);
}

static bool version_from_db(const char *path, const char *pkg_key, const char *ver_key,
			    const char *name, char *dst, size_t size)
{
	size_t pkg_len = strlen(pkg_key), ver_len = strlen(ver_key), name_len = strlen(name);
	FILE *f = fopen(path, "r");
	char line[256];
	bool in_pkg = false;

	if (!f)
		return false;

	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, pkg_key, pkg_len)) {
			in_pkg = !strncmp(line + pkg_len, name, name_len) &&
				 line[pkg_len + name_len] == '\n';
			continue;
		}

		if (in_pkg && !strncmp(line, ver_key, ver_len)) {
			strncpy(dst, line + ver_len, size - 1);
			dst[size - 1] = '\0';
			dst[strcspn(dst, "\r\n")] = '\0';
			break;
		}
	}

	fclose(f);
	return dst[0] != '\0';
}

static void package_version(const char *name, char *dst, size_t size)
{
	dst[0] = '\0';

	if (version_from_db("/usr/lib/opkg/status", "Package: ", "Version: ", name, dst, size))
		return;

	version_from_db("/lib/apk/db/installed", "P:", "V:", name, dst, size);
}

static void diag_cmd(struct blob_buf *b, const char *name, const char *cmd)
{
	char line[512];
	FILE *f;
	void *arr;

	f = popen(cmd, "r");
	if (!f)
		return;

	arr = blobmsg_open_array(b, name);
	while (fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = '\0';
		if (line[0])
			blobmsg_add_string(b, NULL, line);
	}
	blobmsg_close_array(b, arr);

	pclose(f);
}

static void node_identity_blob(struct blob_buf *b)
{
	char value[MESH_NAME_MAX];
	FILE *f;

	value[0] = 0;
	f = fopen("/proc/sys/kernel/hostname", "r");
	if (f) {
		if (fgets(value, sizeof(value), f))
			value[strcspn(value, "\r\n")] = 0;
		fclose(f);
	}
	blobmsg_add_string(b, "hostname", value);

	release_field("DISTRIB_RELEASE=", value, sizeof(value));
	blobmsg_add_string(b, "os_version", value);
	release_field("DISTRIB_ARCH=", value, sizeof(value));
	blobmsg_add_string(b, "arch", value);
	package_version("roamd", value, sizeof(value));
	blobmsg_add_string(b, "pkg_version", value);
	package_version("luci-app-roamd", value, sizeof(value));
	blobmsg_add_string(b, "ui_version", value);
}

void mesh_node_diag(struct blob_buf *b)
{
	node_identity_blob(b);
	roam_time_update();
	if (mesh.role == MESH_NODE)
		mesh_node_watch_blob(b);

	diag_cmd(b, "hostapd_pkg",
		 "(apk info 2>/dev/null || opkg list-installed 2>/dev/null | awk '{print $1}') | "
		 "grep -xE '(wpad|hostapd)(-(mini|basic|mesh))?(-(openssl|mbedtls|wolfssl))?'");
	diag_cmd(b, "wireless", "uci show wireless 2>/dev/null | grep -v '\\.key='");
	diag_cmd(b, "network", "uci show network 2>/dev/null | grep -vE 'private_key|psk'");
	diag_cmd(b, "dhcp_server", "uci show dhcp 2>/dev/null | grep -E 'ignore|dhcpv4|dhcpv6|\\.ra='");
	diag_cmd(b, "services", "pgrep -l 'dnsmasq|odhcpd|hostapd|wpa_supplicant|dropbear' 2>/dev/null");
	diag_cmd(b, "hostapd_objects", "ubus list 2>/dev/null | grep '^hostapd'");
	diag_cmd(b, "addresses", "ip -o -4 addr show 2>/dev/null | awk '{print $2, $4}'");
	diag_cmd(b, "bridge", "brctl show 2>/dev/null");
	diag_cmd(b, "nat_rules", "nft list ruleset 2>/dev/null | grep -c masquerade");
	diag_cmd(b, "dropbear_conf", "uci show dropbear 2>/dev/null");
	diag_cmd(b, "authorized_keys",
		 "ls -ld /etc/dropbear /etc/dropbear/authorized_keys 2>/dev/null; "
		 "awk '{print NR\": \"length($0)\" bytes, tail \"substr($0, length($0) - 11)}' "
		 "/etc/dropbear/authorized_keys 2>/dev/null");
	diag_cmd(b, "stored_key",
		 "for o in ssh_pubkey ssh_pubkey_rsa; do uci -q get roamd.mesh.$o; done | "
		 "awk '{print length($0)\" bytes, tail \"substr($0, length($0) - 11)}'");
	diag_cmd(b, "roamd_log", "tail -n 60 /tmp/roamd-diag.log 2>/dev/null");
	diag_cmd(b, "install_log", "tail -n 20 /tmp/roamd-install.log 2>/dev/null");
	diag_cmd(b, "syslog",
		 "logread 2>/dev/null | grep -iE 'hostapd|dropbear|roamd|netifd|wpad|udhcpc' | tail -n 90");
}

void mesh_self_info(struct blob_buf *b)
{
	struct sysinfo si;
	char value[32];

	node_identity_blob(b);

	if (!sysinfo(&si))
		blobmsg_add_u32(b, "uptime", si.uptime);

	if (mesh_cmd_line("{ ip -4 -o addr show dev " MESH_BRIDGE " scope global; "
		     "ip -4 -o addr show scope global; } 2>/dev/null | "
		     "awk '$2 !~ /:/ { split($4, a, \"/\"); print a[1]; exit }'",
		     value, sizeof(value)))
		blobmsg_add_string(b, "addr", value);

	if (mesh_cmd_line("cat /sys/class/net/" MESH_BRIDGE "/address 2>/dev/null", value, sizeof(value)))
		blobmsg_add_string(b, "mac", value);

	mesh_radios_dump(b, "radios");
}

/* Fresh measurements of the client towards the access points of other devices. */
static void node_meas_blob(struct blob_buf *b, const struct roam_sta *sta)
{
	void *arr = NULL;
	unsigned int i;

	for (i = 0; i < ROAMD_MEAS_MAX; i++) {
		const struct roam_sta_meas *m = &sta->meas[i];
		char bssid[18];
		void *e;

		if (!m->seen || roam_now - m->seen > roam_meas_fresh())
			continue;

		if (!arr)
			arr = blobmsg_open_array(b, "reports");

		roam_mac_str(m->bssid, bssid, sizeof(bssid));
		e = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "bssid", bssid);
		blobmsg_add_u32(b, "signal", (uint32_t)m->signal);
		blobmsg_add_u32(b, "age", (roam_now - m->seen) / 1000);
		blobmsg_close_table(b, e);
	}

	if (arr)
		blobmsg_close_array(b, arr);
}

void mesh_node_report(struct blob_buf *b)
{
	struct sysinfo si;
	struct roam_sta *sta;
	struct mesh_assoc_idx assoc;
	uint8_t pmac[6];
	void *clients;
	unsigned int count = 0;

	mesh_node_touch();
	mesh_assoc_collect(&assoc);
	if (mesh_parent_mac(pmac))
		mesh_wired_collect(&assoc, pmac);

	blobmsg_add_string(b, "role", mesh_role_name(mesh.role));
	blobmsg_add_string(b, "member_id", mesh.member_id);
	blobmsg_add_string(b, "controller_id", mesh.controller_id);

	node_identity_blob(b);
	blobmsg_add_string(b, "roamd_version", ROAMD_VERSION);

	if (!sysinfo(&si))
		blobmsg_add_u32(b, "uptime", si.uptime);

	clients = blobmsg_open_array(b, "clients");
	for (count = 0; count < assoc.n; count++) {
		const struct mesh_assoc *a = &assoc.e[count];
		void *e = blobmsg_open_table(b, NULL);
		char mac[18];

		roam_mac_str(a->addr, mac, sizeof(mac));

		sta = roam_sta_get(a->addr, false);

		blobmsg_add_string(b, "mac", mac);
		if (!a->wired) {
			blobmsg_add_string(b, "band", roam_band_name(a->band));
			if (sta && sta->bss) {
				enum roam_band band;

				blobmsg_add_u32(b, "signal", sta->band[sta->bss->band].signal);
				blobmsg_add_string(b, "ssid", sta->bss->ssid);
				if (sta->btm_status_at) {
					blobmsg_add_u32(b, "btm_status", (uint32_t)sta->btm_status);
					blobmsg_add_u32(b, "btm_age",
							(roam_now - sta->btm_status_at) / 1000);
				}
				if (roam_policy_btm_paused(sta->addr))
					blobmsg_add_u8(b, "btm_paused", 1);
				node_meas_blob(b, sta);

				for (band = 0; band < BAND_MAX; band++) {
					uint32_t age = 0;
					int signal = roam_sta_signal_seen(sta, band, &age);

					if (signal == ROAMD_NO_SIGNAL)
						continue;

					blobmsg_add_u32(b, band == BAND_LOW ?
							"signal_24" : "signal_5",
							(uint32_t)signal);
					blobmsg_add_u32(b, band == BAND_LOW ?
							"signal_24_age" : "signal_5_age", age);
				}
			}
		}
		mesh_assoc_blob(b, a);
		blobmsg_close_table(b, e);
	}
	blobmsg_close_array(b, clients);

	blobmsg_add_u32(b, "client_count", count);
	blobmsg_add_u32(b, "nbr_count", mesh_neighbors_count());

	clients = blobmsg_open_array(b, "heard");
	avl_for_each_element(&roam_sta_tree, sta, avl) {
		enum roam_band band;

		if (sta->bss)
			continue;

		for (band = 0; band < BAND_MAX; band++) {
			int signal = roam_sta_signal(sta, band);
			void *e;

			if (signal == ROAMD_NO_SIGNAL)
				continue;

			e = blobmsg_open_table(b, NULL);
			blobmsg_add_string(b, "mac", sta->mac);
			blobmsg_add_string(b, "band", roam_band_name(band));
			blobmsg_add_u32(b, "signal", (uint32_t)signal);
			blobmsg_close_table(b, e);
		}
	}
	blobmsg_close_array(b, clients);

	{
		struct mesh_uplink_state up;
		char std[8];
		unsigned int nss, width;

		mesh_uplink_read(&up);

		blobmsg_add_string(b, "connection", up.connection);
		blobmsg_add_string(b, "seg_trunk", mesh_seg_node_trunk());
		blobmsg_add_string(b, "seg_issue", mesh_seg_node_issue());
		blobmsg_add_string(b, "uplink_band", up.air ? mesh_freq_band(up.link.freq) : "");

		if (up.air && up.link.signal)
			blobmsg_add_u32(b, "uplink_signal", (uint32_t)up.link.signal);

		mesh_uplink_phy(up.air ? up.link.rx_bitrate : "", std, sizeof(std), &nss, &width);

		if (std[0]) {
			blobmsg_add_string(b, "uplink_std", std);
			blobmsg_add_u32(b, "uplink_nss", nss);
			blobmsg_add_u32(b, "uplink_width", width);
		}

		if (strcmp(up.connection, "wifi"))
			blobmsg_add_string(b, "via", "controller");
		else if (up.link.bssid[0])
			blobmsg_add_string(b, "via", up.link.bssid);
		else {
			struct mesh_iw_link any;

			mesh_uplink_any(&any);
			blobmsg_add_string(b, "via", any.bssid);
		}
	}

	node_profile(b);
	mesh_aps_dump(b, "aps");
	mesh_radios_dump(b, "radios");
	mesh_log_dump(b, MESH_REPORT_EVENTS);
}
