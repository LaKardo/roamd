#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <libubox/uloop.h>

#include "roamd.h"
#include "mesh.h"

pid_t mesh_spawn_argv(char *const argv[])
{
	pid_t pid = fork();

	if (pid > 0)
		roam_stats.forks++;

	if (pid == 0) {
		int fd = open("/dev/null", O_WRONLY);

		setpgid(0, 0);

		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}

		execv(argv[0], argv);
		_exit(127);
	}

	return pid;
}

pid_t mesh_spawn(const char *script, const char *arg1, const char *arg2)
{
	char *argv[5] = { "/bin/sh", (char *)script, (char *)arg1, (char *)arg2, NULL };

	return mesh_spawn_argv(argv);
}

static void mesh_task_done(struct uloop_process *p, int ret)
{
	struct mesh_task *task = container_of(p, struct mesh_task, proc);

	task->busy = false;
	task->proc.pid = 0;

	if (task->done)
		task->done(task, ret);
}

bool mesh_task_run(struct mesh_task *task, char *const argv[])
{
	pid_t pid;

	if (task->busy)
		return false;

	pid = mesh_spawn_argv(argv);

	if (pid <= 0)
		return false;

	task->proc.pid = pid;
	task->proc.cb = mesh_task_done;
	uloop_process_add(&task->proc);
	task->busy = true;

	return true;
}

bool mesh_task_start(struct mesh_task *task, const char *script,
		     const char *arg1, const char *arg2)
{
	pid_t pid;

	if (task->busy)
		return false;

	pid = mesh_spawn(script, arg1, arg2);
	if (pid <= 0)
		return false;

	task->proc.pid = pid;
	task->proc.cb = mesh_task_done;
	uloop_process_add(&task->proc);
	task->busy = true;

	return true;
}

void mesh_task_stop(struct mesh_task *task)
{
	if (task->busy && task->proc.pid > 0)
		kill(-task->proc.pid, SIGTERM);
}
