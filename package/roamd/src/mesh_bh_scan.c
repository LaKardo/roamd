#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#include <libubox/uloop.h>

#include "roamd.h"
#include "mesh.h"

#define MESH_SCAN_GUARD		25000

/* one iwinfo scan per radio at once, every BSS heard goes to scan_heard */
static void (*scan_heard)(const char *bssid, int signal);

static void scan_result_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct blob_attr *results = NULL, *cur;
	int rem;

	blob_for_each_attr(cur, msg, rem)
		if (!strcmp(blobmsg_name(cur), "results") &&
		    blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
			results = cur;

	if (!results)
		return;

	blobmsg_for_each_attr(cur, results, rem) {
		struct blob_attr *f;
		const char *bssid = NULL;
		int signal = 0;
		int frem;

		if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE)
			continue;

		blobmsg_for_each_attr(f, cur, frem) {
			if (!strcmp(blobmsg_name(f), "bssid") &&
			    blobmsg_type(f) == BLOBMSG_TYPE_STRING)
				bssid = blobmsg_get_string(f);
			else if (!strcmp(blobmsg_name(f), "signal") &&
				 blobmsg_type(f) == BLOBMSG_TYPE_INT32)
				signal = (int32_t)blobmsg_get_u32(f);
		}

		if (bssid && signal)
			scan_heard(bssid, signal);
	}
}

#define SCAN_REQ_MAX	4

static struct ubus_request scan_reqs[SCAN_REQ_MAX];
static unsigned int scan_outstanding;
static unsigned int scan_armed;
static void (*scan_after)(void);
static struct uloop_timeout scan_guard;

static void scan_finish(void)
{
	void (*done)(void) = scan_after;

	uloop_timeout_cancel(&scan_guard);
	scan_outstanding = 0;
	scan_armed = 0;
	scan_after = NULL;

	if (done)
		done();
}

static void scan_guard_cb(struct uloop_timeout *t)
{
	unsigned int i;

	for (i = 0; i < scan_armed; i++)
		ubus_abort_request(ubus_ctx, &scan_reqs[i]);

	roam_log(ROAM_L_INFO, "mesh: backhaul scan timed out");
	scan_finish();
}

static void scan_complete_cb(struct ubus_request *req, int ret)
{
	if (scan_outstanding && !--scan_outstanding)
		scan_finish();
}

void mesh_bh_scan(void (*heard)(const char *bssid, int signal), void (*done)(void))
{
	static struct blob_buf b;
	DIR *d = opendir("/sys/class/net");
	char seen[SCAN_REQ_MAX][IFNAMSIZ];
	unsigned int n_seen = 0, i;
	struct dirent *de;
	uint32_t id;

	scan_heard = heard;
	scan_after = done;
	scan_outstanding = 0;
	scan_armed = 0;

	if (!d || ubus_lookup_id(ubus_ctx, "iwinfo", &id)) {
		if (d)
			closedir(d);

		scan_finish();

		return;
	}

	while ((de = readdir(d)) && n_seen < SCAN_REQ_MAX) {
		char path[320], link[128], *phy;
		bool dup = false;
		ssize_t len;

		snprintf(path, sizeof(path), "/sys/class/net/%s/phy80211", de->d_name);
		len = readlink(path, link, sizeof(link) - 1);
		if (len <= 0)
			continue;

		link[len] = 0;
		phy = strrchr(link, '/');
		phy = phy ? phy + 1 : link;

		for (i = 0; i < n_seen && !dup; i++)
			dup = !strcmp(seen[i], phy);

		if (dup)
			continue;

		snprintf(seen[n_seen], IFNAMSIZ, "%.*s", IFNAMSIZ - 1, phy);

		blob_buf_init(&b, 0);
		blobmsg_add_string(&b, "device", de->d_name);

		if (ubus_invoke_async(ubus_ctx, id, "scan", b.head, &scan_reqs[n_seen]))
			continue;

		scan_reqs[n_seen].data_cb = scan_result_cb;
		scan_reqs[n_seen].complete_cb = scan_complete_cb;
		ubus_complete_request_async(ubus_ctx, &scan_reqs[n_seen]);
		scan_outstanding++;
		n_seen++;
	}

	closedir(d);
	scan_armed = scan_outstanding;

	if (!scan_outstanding) {
		scan_finish();

		return;
	}

	scan_guard.cb = scan_guard_cb;
	uloop_timeout_set(&scan_guard, MESH_SCAN_GUARD);
}
