#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <netinet/ether.h>

#include "roamd.h"
#include "mesh.h"

static const char *bss_nr_hex(struct blob_attr *nr)
{
	struct blob_attr *cur;
	const char *best = NULL;
	size_t best_len = 0;
	int rem;

	if (!nr)
		return NULL;

	blobmsg_for_each_attr(cur, nr, rem) {
		if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
			const char *s = blobmsg_get_string(cur);
			size_t len = strlen(s);

			if (len > best_len) {
				best_len = len;
				best = s;
			}
		}
	}

	return best;
}

void mesh_aps_dump(struct blob_buf *b, const char *name)
{
	struct roam_bss *bss;
	void *arr = blobmsg_open_array(b, name);

	list_for_each_entry(bss, &roam_bss_list, list) {
		const char *nr;
		char bssid[18];
		void *e;

		if (!bss->ssid[0])
			continue;

		nr = bss_nr_hex(bss->nr);
		e = blobmsg_open_table(b, NULL);

		roam_mac_str(bss->bssid, bssid, sizeof(bssid));

		blobmsg_add_string(b, "ifname", bss->ifname);
		blobmsg_add_string(b, "bssid", bssid);
		blobmsg_add_string(b, "ssid", bss->ssid);
		blobmsg_add_u32(b, "channel", bss->channel);
		blobmsg_add_string(b, "band", roam_band_name(bss->band));
		blobmsg_add_u8(b, "neighbor_report", !!bss->nr);
		if (nr)
			blobmsg_add_string(b, "nr", nr);
		blobmsg_close_table(b, e);
	}

	blobmsg_close_array(b, arr);
}

struct mesh_neighbor {
	char bssid[18];
	char ssid[MESH_SSID_MAX];
	char nr[160];
};

static struct mesh_neighbor mesh_nbr[MESH_NBR_MAX];
static unsigned int mesh_nbr_n;

static bool nr_valid(const char *nr)
{
	return mesh_valid_hex(nr) && strlen(nr) < sizeof(((struct mesh_neighbor *)0)->nr);
}

void mesh_neighbors_set(struct blob_attr *arr)
{
	enum { N_BSSID, N_SSID, N_NR, __N_MAX };
	static const struct blobmsg_policy np[__N_MAX] = {
		[N_BSSID] = { "bssid", BLOBMSG_TYPE_STRING },
		[N_SSID] = { "ssid", BLOBMSG_TYPE_STRING },
		[N_NR] = { "nr", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *cur;
	int rem;

	mesh_nbr_n = 0;
	if (!arr)
		return;

	blobmsg_for_each_attr(cur, arr, rem) {
		struct blob_attr *tb[__N_MAX];
		struct mesh_neighbor *n;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE || mesh_nbr_n >= MESH_NBR_MAX)
			continue;

		blobmsg_parse(np, __N_MAX, tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[N_BSSID] || !tb[N_NR] ||
		    !mesh_valid_mac(blobmsg_get_string(tb[N_BSSID])) ||
		    !nr_valid(blobmsg_get_string(tb[N_NR])))
			continue;

		n = &mesh_nbr[mesh_nbr_n++];
		memset(n, 0, sizeof(*n));
		strncpy(n->bssid, blobmsg_get_string(tb[N_BSSID]), sizeof(n->bssid) - 1);
		if (tb[N_SSID])
			strncpy(n->ssid, blobmsg_get_string(tb[N_SSID]), sizeof(n->ssid) - 1);
		strncpy(n->nr, blobmsg_get_string(tb[N_NR]), sizeof(n->nr) - 1);
	}
}

unsigned int mesh_neighbors_count(void)
{
	return mesh_nbr_n;
}

static bool nbr_is_local(const char *bssid)
{
	struct roam_bss *bss;

	list_for_each_entry(bss, &roam_bss_list, list) {
		char bs[18];

		roam_mac_str(bss->bssid, bs, sizeof(bs));
		if (!strcasecmp(bs, bssid))
			return true;
	}

	return false;
}

static unsigned int hex_byte(const char *s)
{
	unsigned int v = 0;

	sscanf(s, "%2x", &v);

	return v;
}

/* Remote APs of this SSID with the channel the neighbor report element gives them. */
unsigned int mesh_neighbors_remote(const char *ssid, struct mesh_nbr_info *out, unsigned int max)
{
	unsigned int i, n = 0;

	for (i = 0; i < mesh_nbr_n && n < max; i++) {
		struct mesh_neighbor *nb = &mesh_nbr[i];
		struct ether_addr *ea;

		if (ssid && nb->ssid[0] && strcmp(nb->ssid, ssid))
			continue;
		if (nbr_is_local(nb->bssid) || strlen(nb->nr) < 26)
			continue;

		ea = ether_aton(nb->bssid);
		if (!ea)
			continue;

		memcpy(out[n].bssid, ea->ether_addr_octet, 6);
		out[n].op_class = hex_byte(nb->nr + 20);
		out[n].channel = hex_byte(nb->nr + 22);
		if (!out[n].op_class || !out[n].channel)
			continue;

		n++;
	}

	return n;
}

void mesh_neighbors_append(struct blob_buf *b, const char *ssid, int *count, int max)
{
	unsigned int i;

	for (i = 0; i < mesh_nbr_n && *count < max; i++) {
		struct mesh_neighbor *n = &mesh_nbr[i];
		void *e;

		if (ssid && n->ssid[0] && strcmp(n->ssid, ssid))
			continue;
		if (nbr_is_local(n->bssid))
			continue;

		e = blobmsg_open_array(b, NULL);
		blobmsg_add_string(b, NULL, n->bssid);
		blobmsg_add_string(b, NULL, n->ssid);
		blobmsg_add_string(b, NULL, n->nr);
		blobmsg_close_array(b, e);
		(*count)++;
	}
}

#define MESH_PEER_STA_MAX	256
#define MESH_PEER_STA_TTL	60000

static uint8_t peer_sta[MESH_PEER_STA_MAX][6];
static unsigned int peer_sta_n;
static uint64_t peer_sta_at;

void mesh_peer_clients_set(struct blob_attr *arr)
{
	struct blob_attr *cur;
	int rem;

	peer_sta_n = 0;
	if (!arr)
		return;

	roam_time_update();
	peer_sta_at = roam_now;

	blobmsg_for_each_attr(cur, arr, rem) {
		struct ether_addr ea;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING || peer_sta_n >= MESH_PEER_STA_MAX)
			continue;

		if (!ether_aton_r(blobmsg_get_string(cur), &ea))
			continue;

		memcpy(peer_sta[peer_sta_n++], ea.ether_addr_octet, 6);
	}
}

bool mesh_peer_client(const uint8_t *addr)
{
	unsigned int i;

	if (!peer_sta_n || roam_now - peer_sta_at > MESH_PEER_STA_TTL)
		return false;

	for (i = 0; i < peer_sta_n; i++)
		if (!memcmp(peer_sta[i], addr, 6))
			return true;

	return false;
}
