#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "roamd.h"
#include "mesh.h"

static bool ifname_safe(const char *name)
{
	const char *p;

	if (!name[0] || strlen(name) >= 16)
		return false;

	for (p = name; *p; p++)
		if (!isalnum((unsigned char)*p) && !strchr("-_.@", *p))
			return false;

	return true;
}

static bool iw_link_read(const char *ifname, struct mesh_iw_link *l)
{
	char cmd[64], line[192];
	FILE *f;

	memset(l, 0, sizeof(*l));

	if (!ifname_safe(ifname))
		return false;

	snprintf(cmd, sizeof(cmd), "iw dev %s link 2>/dev/null", ifname);
	f = popen(cmd, "r");
	if (!f)
		return false;

	roam_stats.forks++;

	while (fgets(line, sizeof(line), f)) {
		char *p = line + strspn(line, " \t");

		p[strcspn(p, "\r\n")] = '\0';

		if (sscanf(p, "Connected to %17[0-9a-fA-F:]", l->bssid) == 1)
			continue;
		if (sscanf(p, "signal: %d", &l->signal) == 1)
			continue;
		if (sscanf(p, "freq: %d", &l->freq) == 1)
			continue;
		if (!strncmp(p, "rx bitrate: ", 12))
			snprintf(l->rx_bitrate, sizeof(l->rx_bitrate), "%s", p + 12);
	}

	pclose(f);

	return l->bssid[0] != '\0';
}

/* wireless bridge ports, as the old shell loop over /sys/class/net/<i>/brport found them */
static unsigned int sta_ifaces(char out[][16], unsigned int max)
{
	DIR *d = opendir("/sys/class/net");
	struct dirent *de;
	unsigned int n = 0;

	if (!d)
		return 0;

	while (n < max && (de = readdir(d))) {
		char path[300];
		struct stat st;

		if (de->d_name[0] == '.' || strlen(de->d_name) >= 16)
			continue;

		snprintf(path, sizeof(path), "/sys/class/net/%s/brport", de->d_name);
		if (stat(path, &st))
			continue;

		snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", de->d_name);
		if (stat(path, &st))
			continue;

		snprintf(out[n++], 16, "%.15s", de->d_name);
	}

	closedir(d);

	return n;
}

static bool brport_forwarding(const char *ifname)
{
	char path[64], buf[8] = "";
	FILE *f;

	snprintf(path, sizeof(path), "/sys/class/net/%.15s/brport/state", ifname);
	f = fopen(path, "r");
	if (!f)
		return false;

	if (!fgets(buf, sizeof(buf), f))
		buf[0] = '\0';
	fclose(f);

	return atoi(buf) == 3;
}

/* the first connected wireless bridge port */
bool mesh_uplink_any(struct mesh_iw_link *l)
{
	char ifs[MESH_BRPORT_MAX][16];
	unsigned int n = sta_ifaces(ifs, MESH_BRPORT_MAX), i;

	for (i = 0; i < n; i++)
		if (iw_link_read(ifs[i], l))
			return true;

	return false;
}

bool mesh_node_uplink(struct mesh_uplink *up)
{
	uint8_t mac[6];

	return mesh_parent_mac(mac) && mesh_bridge_port_of(mac, up);
}

bool mesh_node_wired_uplink(void)
{
	struct mesh_uplink up;

	return mesh_node_uplink(&up) && !up.wireless;
}

void mesh_uplink_phy(const char *line, char *std, size_t len, unsigned int *nss,
		     unsigned int *width)
{
	const char *p;

	snprintf(std, len, "%s", "");
	*nss = 0;
	*width = 0;

	if (!line[0])
		return;

	if ((p = strstr(line, "HE-MCS"))) {
		snprintf(std, len, "11ax");
		p = strstr(line, "HE-NSS");
	} else if ((p = strstr(line, "VHT-MCS"))) {
		snprintf(std, len, "11ac");
		p = strstr(line, "VHT-NSS");
	} else if ((p = strstr(line, "MCS"))) {
		snprintf(std, len, "11n");
		*nss = (unsigned int)(atoi(p + 3) / 8 + 1);
		p = NULL;
	} else {
		snprintf(std, len, "11a/g");
		*nss = 1;
	}

	if (p)
		*nss = (unsigned int)atoi(p + 6);

	if (strstr(line, "160MHz"))
		*width = 160;
	else if (strstr(line, "80MHz"))
		*width = 80;
	else if (strstr(line, "40MHz"))
		*width = 40;
	else
		*width = 20;
}

void mesh_uplink_read(struct mesh_uplink_state *s)
{
	char ifs[MESH_BRPORT_MAX][16];
	struct mesh_uplink up;
	unsigned int n, i;

	memset(s, 0, sizeof(*s));
	s->connection = "wired";

	if (mesh.role != MESH_NODE)
		return;

	if (mesh_node_uplink(&up)) {
		if (up.wireless) {
			s->connection = "wifi";
			s->air = true;
			iw_link_read(up.ifname, &s->link);
		}
		return;
	}

	n = sta_ifaces(ifs, MESH_BRPORT_MAX);
	for (i = 0; i < n; i++) {
		if (!iw_link_read(ifs[i], &s->link))
			continue;

		if (brport_forwarding(ifs[i])) {
			s->connection = "wifi";
			return;
		}
	}

	memset(&s->link, 0, sizeof(s->link));
}

const char *mesh_freq_band(int freq)
{
	if (!freq)
		return "";

	return freq < 3000 ? "2.4" : "5";
}

const char *mesh_node_uplink_band(void)
{
	struct mesh_uplink_state s;

	mesh_uplink_read(&s);

	return s.air ? mesh_freq_band(s.link.freq) : "";
}
