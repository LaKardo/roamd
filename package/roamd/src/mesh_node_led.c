#include <stdio.h>
#include <string.h>

#include "roamd.h"
#include "mesh.h"

static char link_led[96];
static char link_led_max[16] = "255";
static bool link_led_known;
static int link_led_on = -1;

static void link_led_write(const char *node, const char *value)
{
	char path[128];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", link_led, node);
	f = fopen(path, "w");
	if (!f)
		return;

	fputs(value, f);
	fclose(f);
}

static void link_led_read_max(void)
{
	char path[128], buf[16];
	FILE *f;

	snprintf(path, sizeof(path), "%s/max_brightness", link_led);
	f = fopen(path, "r");
	if (!f)
		return;

	if (fgets(buf, sizeof(buf), f)) {
		buf[strcspn(buf, "\r\n")] = '\0';
		if (buf[0])
			snprintf(link_led_max, sizeof(link_led_max), "%s", buf);
	}

	fclose(f);
}

static void link_led_find(void)
{
	char name[48];

	link_led_known = true;

	if (!mesh_cmd_line(
		"uci -q show system | sed -n \"s/.*\\.sysfs='\\(.*\\)'$/\\1/p\" | "
		"while read -r l; do case \"$l\" in *wan*|*internet*|*net*) "
		"[ -e \"/sys/class/leds/$l/brightness\" ] && { echo \"$l\"; break; };; esac; done",
		name, sizeof(name)) || !name[0])
		return;

	snprintf(link_led, sizeof(link_led), "/sys/class/leds/%s", name);

	link_led_read_max();
	link_led_write("trigger", "none");
	roam_log(ROAM_L_INFO, "mesh: link indicator %s", name);
}

void mesh_node_led_set(bool on)
{
	if (!link_led_known)
		link_led_find();

	if (!link_led[0] || link_led_on == (int)on)
		return;

	link_led_write("brightness", on ? link_led_max : "0");
	link_led_on = on;
}
