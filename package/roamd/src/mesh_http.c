#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <libubox/blobmsg_json.h>

#include "roamd.h"
#include "mesh.h"

#define HTTP_PORT	"80"
#define HTTP_RESP_MAX	65536
#define HTTP_NULL_SID	"00000000000000000000000000000000"

static int http_connect(const char *addr, int timeout_ms)
{
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
				  .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV };
	struct addrinfo *res = NULL;
	struct timeval tv = { .tv_sec = timeout_ms / 1000,
			      .tv_usec = (timeout_ms % 1000) * 1000 };
	int fd, rc;

	if (getaddrinfo(addr, HTTP_PORT, &hints, &res) || !res)
		return -1;

	fd = socket(res->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		freeaddrinfo(res);
		return -1;
	}

	rc = connect(fd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	if (rc && errno == EINPROGRESS) {
		struct pollfd pfd = { .fd = fd, .events = POLLOUT };
		socklen_t len = sizeof(int);
		int err = 0;

		do {
			rc = poll(&pfd, 1, timeout_ms);
		} while (rc < 0 && errno == EINTR);

		rc = rc > 0 && !getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) && !err ? 0 : -1;
	}

	if (rc) {
		close(fd);
		return -1;
	}

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	return fd;
}

static bool http_write_all(int fd, const char *data, size_t len)
{
	while (len) {
		ssize_t n = write(fd, data, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return false;

		data += n;
		len -= n;
	}

	return true;
}

static char *http_post(const char *addr, const char *body, int timeout_ms)
{
	char host[MESH_ADDR_MAX + 2], head[512], *resp, *payload;
	size_t used = 0;
	const char *pct;
	int fd;

	pct = strchr(addr, '%');
	if (strchr(addr, ':'))
		snprintf(host, sizeof(host), "[%.*s]",
			 pct ? (int)(pct - addr) : (int)strlen(addr), addr);
	else
		snprintf(host, sizeof(host), "%s", addr);

	snprintf(head, sizeof(head),
		 "POST /ubus HTTP/1.0\r\n"
		 "Host: %s\r\n"
		 "Content-Type: application/json\r\n"
		 "Content-Length: %zu\r\n"
		 "Connection: close\r\n\r\n", host, strlen(body));

	fd = http_connect(addr, timeout_ms);
	if (fd < 0)
		return NULL;

	resp = calloc(1, HTTP_RESP_MAX + 1);
	if (!resp || !http_write_all(fd, head, strlen(head)) ||
	    !http_write_all(fd, body, strlen(body))) {
		close(fd);
		free(resp);
		return NULL;
	}

	while (used < HTTP_RESP_MAX) {
		ssize_t n = read(fd, resp + used, HTTP_RESP_MAX - used);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;

		used += n;
	}

	close(fd);
	resp[used] = 0;

	if (strncmp(resp, "HTTP/1.", 7) || strncmp(resp + 8, " 200", 4)) {
		free(resp);
		return NULL;
	}

	payload = strstr(resp, "\r\n\r\n");
	if (!payload) {
		free(resp);
		return NULL;
	}

	memmove(resp, payload + 4, strlen(payload + 4) + 1);

	return resp;
}

int mesh_http_ubus(const char *addr, const char *sid, const char *object, const char *method,
		   const char *args, struct blob_buf *doc, struct blob_attr **data,
		   int timeout_ms)
{
	struct blob_buf req = { 0 };
	struct blob_attr *cur, *result = NULL;
	char *body, *resp;
	void *arr, *tbl;
	int rem, status = -1;

	if (data)
		*data = NULL;

	blob_buf_init(&req, 0);
	blobmsg_add_string(&req, "jsonrpc", "2.0");
	blobmsg_add_u32(&req, "id", 1);
	blobmsg_add_string(&req, "method", "call");
	arr = blobmsg_open_array(&req, "params");
	blobmsg_add_string(&req, NULL, sid ? sid : HTTP_NULL_SID);
	blobmsg_add_string(&req, NULL, object);
	blobmsg_add_string(&req, NULL, method);
	tbl = blobmsg_open_table(&req, NULL);
	if (args && args[0] && !blobmsg_add_json_from_string(&req, args)) {
		blob_buf_free(&req);
		return -1;
	}
	blobmsg_close_table(&req, tbl);
	blobmsg_close_array(&req, arr);

	body = blobmsg_format_json(req.head, true);
	blob_buf_free(&req);
	if (!body)
		return -1;

	resp = http_post(addr, body, timeout_ms);
	free(body);
	if (!resp)
		return -1;

	blob_buf_init(doc, 0);
	if (!blobmsg_add_json_from_string(doc, resp)) {
		free(resp);
		return -1;
	}
	free(resp);

	blob_for_each_attr(cur, doc->head, rem)
		if (!strcmp(blobmsg_name(cur), "result") &&
		    blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY)
			result = cur;

	if (!result)
		return -1;

	rem = blobmsg_data_len(result);
	__blob_for_each_attr(cur, blobmsg_data(result), rem) {
		if (status < 0) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_INT32)
				return -1;

			status = (int)blobmsg_get_u32(cur);
			continue;
		}

		if (data && blobmsg_type(cur) == BLOBMSG_TYPE_TABLE)
			*data = cur;
		break;
	}

	return status;
}

bool mesh_http_login(const char *addr, char *sid, size_t len, int timeout_ms)
{
	struct blob_buf doc = { 0 };
	struct blob_attr *data, *cur;
	bool ok = false;
	int rem;

	if (mesh_http_ubus(addr, NULL, "session", "login",
			   "{\"username\":\"root\",\"password\":\"\"}", &doc, &data,
			   timeout_ms) || !data)
		goto out;

	blobmsg_for_each_attr(cur, data, rem)
		if (!strcmp(blobmsg_name(cur), "ubus_rpc_session") &&
		    blobmsg_type(cur) == BLOBMSG_TYPE_STRING) {
			snprintf(sid, len, "%s", blobmsg_get_string(cur));
			ok = mesh_valid_hex(sid);
		}

out:
	blob_buf_free(&doc);

	return ok;
}

static struct blob_attr *attr_child(struct blob_attr *table, const char *name, int type)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return NULL;

	blobmsg_for_each_attr(cur, table, rem)
		if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == type)
			return cur;

	return NULL;
}

int mesh_http_dropbear_iface(const char *addr, const char *sid, char *sections, size_t len,
			     int timeout_ms)
{
	struct blob_buf doc = { 0 };
	struct blob_attr *data, *values, *cur;
	int rem, found = 0;

	if (sections && len)
		sections[0] = 0;

	if (mesh_http_ubus(addr, sid, "uci", "get", "{\"config\":\"dropbear\"}", &doc, &data,
			   timeout_ms)) {
		blob_buf_free(&doc);
		return -1;
	}

	values = attr_child(data, "values", BLOBMSG_TYPE_TABLE);

	if (values)
		blobmsg_for_each_attr(cur, values, rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_TABLE ||
			    !attr_child(cur, "Interface", BLOBMSG_TYPE_STRING) ||
			    !mesh_valid_id(blobmsg_name(cur)))
				continue;

			found++;

			if (sections) {
				size_t used = strlen(sections);

				snprintf(sections + used, len - used, "%s%s", used ? " " : "",
					 blobmsg_name(cur));
			}
		}

	blob_buf_free(&doc);

	return found;
}

char *mesh_http_file_read(const char *addr, const char *sid, const char *path, int timeout_ms)
{
	struct blob_buf doc = { 0 };
	struct blob_attr *data, *text;
	char args[256], *out = NULL;

	snprintf(args, sizeof(args), "{\"path\":\"%s\"}", path);

	if (!mesh_http_ubus(addr, sid, "file", "read", args, &doc, &data, timeout_ms)) {
		text = attr_child(data, "data", BLOBMSG_TYPE_STRING);
		if (text)
			out = strdup(blobmsg_get_string(text));
	}

	blob_buf_free(&doc);

	return out;
}

char *mesh_http_board(const char *addr, const char *sid, int timeout_ms)
{
	struct blob_buf doc = { 0 };
	struct blob_attr *data;
	char *out = NULL;

	if (!mesh_http_ubus(addr, sid, "system", "board", NULL, &doc, &data, timeout_ms) && data)
		out = blobmsg_format_json(data, true);

	blob_buf_free(&doc);

	return out;
}

bool mesh_http_ssh_open(const char *addr, int timeout_ms)
{
	struct blob_buf doc = { 0 };
	char sid[40], sections[256], args[160], *s, *save = NULL;
	int n;

	if (!mesh_http_login(addr, sid, sizeof(sid), timeout_ms))
		return false;

	n = mesh_http_dropbear_iface(addr, sid, sections, sizeof(sections), timeout_ms);
	if (n < 0)
		return false;

	for (s = strtok_r(sections, " ", &save); s; s = strtok_r(NULL, " ", &save)) {
		snprintf(args, sizeof(args),
			 "{\"config\":\"dropbear\",\"section\":\"%s\",\"option\":\"Interface\"}", s);

		if (mesh_http_ubus(addr, sid, "uci", "delete", args, &doc, NULL, timeout_ms)) {
			blob_buf_free(&doc);
			return false;
		}
	}

	if (n && mesh_http_ubus(addr, sid, "uci", "commit", "{\"config\":\"dropbear\"}", &doc,
				NULL, timeout_ms)) {
		blob_buf_free(&doc);
		return false;
	}

	if (mesh_http_ubus(addr, sid, "rc", "init",
			   "{\"name\":\"dropbear\",\"action\":\"restart\"}", &doc, NULL, timeout_ms) &&
	    mesh_http_ubus(addr, sid, "file", "exec",
			   "{\"command\":\"/etc/init.d/dropbear\",\"params\":[\"restart\"]}", &doc,
			   NULL, timeout_ms)) {
		blob_buf_free(&doc);
		return false;
	}

	blob_buf_free(&doc);

	return true;
}
