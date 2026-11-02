#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "roamd.h"
#include "mesh.h"

#define SSH_AUTHORIZED	"/etc/dropbear/authorized_keys"
#define AUTHORIZED_LINE_MAX	(MESH_PUBKEY_MAX + 512)

static bool authorized_has(const char *key)
{
	char line[AUTHORIZED_LINE_MAX];
	bool found = false;
	FILE *f = fopen(SSH_AUTHORIZED, "r");

	while (f && !found && fgets(line, sizeof(line), f)) {
		line[strcspn(line, "\r\n")] = '\0';
		found = !strcmp(line, key);
	}

	if (f)
		fclose(f);

	return found;
}

static void authorized_drop(const char *key)
{
	char line[AUTHORIZED_LINE_MAX];
	FILE *in, *out;

	in = fopen(SSH_AUTHORIZED, "r");
	if (!in)
		return;

	out = fopen(SSH_AUTHORIZED ".roamd", "w");
	if (!out) {
		fclose(in);
		return;
	}
	fchmod(fileno(out), 0600);

	while (fgets(line, sizeof(line), in)) {
		size_t len = strcspn(line, "\r\n");

		if (len == strlen(key) && !strncmp(line, key, len))
			continue;

		fputs(line, out);
	}

	fclose(in);
	if (fclose(out)) {
		unlink(SSH_AUTHORIZED ".roamd");
		return;
	}
	rename(SSH_AUTHORIZED ".roamd", SSH_AUTHORIZED);
}

void mesh_node_key_ensure(void)
{
	unsigned int k;
	FILE *f;

	if (mesh.role != MESH_NODE)
		return;

	for (k = 0; k < __MESH_KEY_MAX; k++) {
		if (!mesh.ssh_pubkey[k][0] || authorized_has(mesh.ssh_pubkey[k]))
			continue;

		mkdir("/etc/dropbear", 0700);

		f = fopen(SSH_AUTHORIZED, "a");
		if (!f)
			return;

		fprintf(f, "%s\n", mesh.ssh_pubkey[k]);
		fclose(f);
		chmod(SSH_AUTHORIZED, 0600);

		roam_log(ROAM_L_INFO, "mesh: controller key %s restored in %s",
			 mesh_key_fields[k], SSH_AUTHORIZED);
	}
}

static bool pubkey_valid(const char *key)
{
	static const char *const types[] = { "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 " };
	size_t i, len = strlen(key);
	const char *p = NULL;

	if (len >= MESH_PUBKEY_MAX)
		return false;

	for (i = 0; i < ARRAY_SIZE(types) && !p; i++)
		if (!strncmp(key, types[i], strlen(types[i])))
			p = key + strlen(types[i]);

	if (!p || !*p)
		return false;

	for (; *p && *p != ' '; p++)
		if (!isalnum((unsigned char)*p) && *p != '+' && *p != '/' && *p != '=')
			return false;

	for (; *p; p++)
		if (*p < 0x20 || *p > 0x7e)
			return false;

	return true;
}

static bool root_hash_valid(const char *hash)
{
	size_t i;

	if (hash[0] != '$' || strlen(hash) > 256)
		return false;

	for (i = 0; hash[i]; i++)
		if (!isalnum((unsigned char)hash[i]) && !strchr("$./=", hash[i]))
			return false;

	return true;
}

static void apply_pubkey(enum mesh_key k, struct blob_attr *attr)
{
	const char *pubkey = attr ? blobmsg_get_string(attr) : NULL;
	struct uci_session u;

	if (!pubkey || !pubkey[0] || !strcmp(mesh.ssh_pubkey[k], pubkey))
		return;

	if (!pubkey_valid(pubkey)) {
		roam_log(ROAM_L_ERR, "mesh: malformed %s from the controller rejected",
			 mesh_key_fields[k]);
		return;
	}

	if (mesh.ssh_pubkey[k][0])
		authorized_drop(mesh.ssh_pubkey[k]);

	snprintf(mesh.ssh_pubkey[k], sizeof(mesh.ssh_pubkey[k]), "%s", pubkey);

	if (uci_session_open(&u, "roamd")) {
		uci_session_add(&u, "mesh", "mesh");
		uci_session_set(&u, "mesh", mesh_key_fields[k], pubkey);
		uci_session_close(&u);
	}
}

bool mesh_node_creds_apply(struct blob_attr *cred)
{
	enum { CP_HASH, CP_PUBKEY, CP_PUBKEY_RSA, __CP_MAX };
	static const struct blobmsg_policy cp[__CP_MAX] = {
		[CP_HASH] = { .name = "root_hash", .type = BLOBMSG_TYPE_STRING },
		[CP_PUBKEY] = { .name = "ssh_pubkey", .type = BLOBMSG_TYPE_STRING },
		[CP_PUBKEY_RSA] = { .name = "ssh_pubkey_rsa", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__CP_MAX];
	struct blob_attr *rh;
	const char *hash;
	FILE *in, *out;
	char line[512];
	bool changed = false, wrote = false;

	if (!cred)
		return false;

	blobmsg_parse(cp, __CP_MAX, tb, blobmsg_data(cred), blobmsg_data_len(cred));

	apply_pubkey(MESH_KEY_ED25519, tb[CP_PUBKEY]);
	apply_pubkey(MESH_KEY_RSA, tb[CP_PUBKEY_RSA]);
	mesh_node_key_ensure();

	rh = tb[CP_HASH];
	if (!rh)
		return false;
	hash = blobmsg_get_string(rh);
	if (!root_hash_valid(hash)) {
		roam_log(ROAM_L_ERR, "mesh: malformed root password hash rejected");
		return false;
	}

	in = fopen("/etc/shadow", "r");
	if (!in)
		return false;
	out = fopen("/etc/shadow.roamd", "w");
	if (!out) {
		fclose(in);
		return false;
	}
	fchmod(fileno(out), 0600);

	while (fgets(line, sizeof(line), in)) {
		if (!strncmp(line, "root:", 5)) {
			char *p1 = line + 5;
			char *p2 = strchr(p1, ':');

			if (p2) {
				size_t len = p2 - p1;

				if (strlen(hash) != len || strncmp(p1, hash, len))
					changed = true;
				fprintf(out, "root:%s%s", hash, p2);
				wrote = true;
				continue;
			}
		}
		fputs(line, out);
	}

	fclose(in);
	if (fclose(out))
		wrote = false;

	if (wrote && changed) {
		rename("/etc/shadow.roamd", "/etc/shadow");
		return true;
	}

	unlink("/etc/shadow.roamd");
	return false;
}
