#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <libubox/ustream-ssl.h>

#include "roamd.h"
#include "mesh.h"

void mesh_dir_ensure(const char *path)
{
	mkdir(MESH_RUN_DIR, 0755);

	if (path && strcmp(path, MESH_RUN_DIR))
		mkdir(path, 0755);
}

struct ustream_ssl_ctx *mesh_ssl_context(const struct ustream_ssl_ops **ops)
{
	static const struct ustream_ssl_ops *cached;

	if (!cached) {
		void *dl = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);

		cached = dl ? dlsym(dl, "ustream_ssl_ops") : NULL;

		if (!cached)
			return NULL;
	}

	*ops = cached;

	return cached->context_new(false);
}

char *mesh_slurp(const char *path, size_t max)
{
	struct stat st;
	char *buf;
	int fd, n;
	size_t size = max;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (!fstat(fd, &st) && st.st_size >= 0 && (size_t)st.st_size < size)
		size = st.st_size;

	buf = malloc(size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}

	n = read(fd, buf, size);
	close(fd);
	if (n < 0) {
		free(buf);
		return NULL;
	}

	buf[n] = '\0';
	return buf;
}

void mesh_unquote(char *s)
{
	size_t len = strlen(s);

	if (len >= 2 && (s[0] == '"' || s[0] == '\'') && s[len - 1] == s[0]) {
		memmove(s, s + 1, len - 2);
		s[len - 2] = 0;
	}
}

const char *mesh_role_name(enum mesh_role role)
{
	return role == MESH_NODE ? "node" : "controller";
}

const char *mesh_self_node_id(void)
{
	if (mesh.role == MESH_NODE && mesh.member_id[0])
		return mesh.member_id;

	return "controller";
}

void mesh_ft_nasid(const char *node, uint8_t band, char *out, size_t len)
{
	snprintf(out, len, "%s-%s", node, band == MESH_BAND_5 ? "5" : "2");
}

bool mesh_chain_has(const char *chain, const char *id)
{
	size_t len = strlen(id);
	const char *p = chain;

	while (len && (p = strstr(p, id))) {
		if ((p == chain || p[-1] == '-') && (p[len] == '\0' || p[len] == '-'))
			return true;

		p += len;
	}

	return false;
}

bool mesh_valid_id(const char *s)
{
	size_t i;

	if (!s || !s[0] || strlen(s) >= MESH_ID_MAX)
		return false;

	for (i = 0; s[i]; i++)
		if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_')
			return false;

	return true;
}

bool mesh_valid_task(const char *s)
{
	size_t i;

	if (!s || !s[0] || strlen(s) >= 32)
		return false;

	for (i = 0; s[i]; i++)
		if (!isdigit((unsigned char)s[i]))
			return false;

	return true;
}

bool mesh_valid_mac(const char *s)
{
	struct ether_addr ea;

	return s && strlen(s) == 17 && ether_aton_r(s, &ea);
}

const char *mesh_shq(char *out, size_t len, const char *s)
{
	size_t used = 0;

	if (!len)
		return "";

	for (; s && *s; s++) {
		const char *piece = *s == '\'' ? "'\\''" : NULL;
		size_t n = piece ? 4 : 1;

		if (used + n >= len) {
			used = 0;
			break;
		}

		if (piece)
			memcpy(out + used, piece, n);
		else
			out[used] = *s;

		used += n;
	}

	out[used] = 0;

	return out;
}

bool mesh_valid_hex(const char *s)
{
	size_t i, len = s ? strlen(s) : 0;

	if (!len || len % 2)
		return false;

	for (i = 0; i < len; i++)
		if (!isxdigit((unsigned char)s[i]))
			return false;

	return true;
}

bool mesh_valid_addr(const char *s)
{
	char host[MESH_ADDR_MAX];
	unsigned char buf[sizeof(struct in6_addr)];
	const char *zone;
	size_t i;

	if (!s || !s[0] || strlen(s) >= sizeof(host))
		return false;

	snprintf(host, sizeof(host), "%s", s);
	zone = strchr(host, '%');
	if (zone) {
		host[zone - host] = 0;
		zone = s + (zone - host) + 1;

		if (!zone[0] || strlen(zone) >= IFNAMSIZ)
			return false;

		for (i = 0; zone[i]; i++)
			if (!isalnum((unsigned char)zone[i]) && !strchr("-_.", zone[i]))
				return false;

		return inet_pton(AF_INET6, host, buf) == 1;
	}

	return inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1;
}

uint8_t mesh_band_bit(const char *name)
{
	if (!name || !name[0])
		return 0;

	return name[0] == '2' ? MESH_BAND_24 : MESH_BAND_5;
}

enum roam_band mesh_band_from_bit(uint8_t bit)
{
	return bit == MESH_BAND_5 ? BAND_HIGH : BAND_LOW;
}

static uint8_t local_band_mask(void)
{
	struct roam_bss *bss;
	uint8_t mask = 0;

	list_for_each_entry(bss, &roam_bss_list, list)
		if (roam_bss_matches(bss))
			mask |= roam_band_bit(bss->band);

	return mask;
}

bool mesh_band_usable(uint8_t bit)
{
	if (!bit)
		return true;

	if (mesh.role == MESH_NODE && mesh.enabled)
		return local_band_mask() & bit;

	return (mesh.band_mask | local_band_mask()) & bit;
}
