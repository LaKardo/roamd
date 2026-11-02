#include <string.h>

#include "roamd.h"
#include "mesh.h"

struct blob_attr *mesh_attr_field(struct blob_attr *table, const char *name, int type)
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

struct blob_attr *mesh_root_field(struct blob_buf *b, const char *name, int type)
{
	struct blob_attr *cur;
	int rem;

	blob_for_each_attr(cur, b->head, rem)
		if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == type)
			return cur;

	return NULL;
}

static const char *str_of(struct blob_attr *cur)
{
	if (blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
		return blobmsg_get_string(cur);

	if (blobmsg_type(cur) == BLOBMSG_TYPE_BOOL)
		return blobmsg_get_bool(cur) ? "true" : "false";

	return NULL;
}

/* a string field, or a boolean as "true"/"false"; json-c keeps one value per key */
const char *mesh_attr_str(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return NULL;

	blobmsg_for_each_attr(cur, table, rem)
		if (!strcmp(blobmsg_name(cur), name))
			return str_of(cur);

	return NULL;
}

const char *mesh_root_str(struct blob_buf *b, const char *name)
{
	struct blob_attr *cur;
	int rem;

	blob_for_each_attr(cur, b->head, rem)
		if (!strcmp(blobmsg_name(cur), name))
			return str_of(cur);

	return NULL;
}

uint32_t mesh_attr_u32(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur = mesh_attr_field(table, name, BLOBMSG_TYPE_INT32);

	return cur ? blobmsg_get_u32(cur) : 0;
}

/* any integer width, or a double, as JSON from another version may give it */
uint64_t mesh_attr_num(struct blob_attr *table, const char *name)
{
	struct blob_attr *cur;
	int rem;

	if (!table)
		return 0;

	blobmsg_for_each_attr(cur, table, rem) {
		if (strcmp(blobmsg_name(cur), name))
			continue;

		switch (blobmsg_type(cur)) {
		case BLOBMSG_TYPE_INT64: return blobmsg_get_u64(cur);
		case BLOBMSG_TYPE_INT32: return blobmsg_get_u32(cur);
		case BLOBMSG_TYPE_INT16: return blobmsg_get_u16(cur);
		case BLOBMSG_TYPE_INT8: return blobmsg_get_u8(cur);
		case BLOBMSG_TYPE_DOUBLE: return (uint64_t)blobmsg_get_double(cur);
		}
		break;
	}

	return 0;
}
