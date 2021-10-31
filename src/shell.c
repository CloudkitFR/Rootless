#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <wait.h>
#include <memory.h>
#include <syscall.h>
#include <errno.h>
#include <grp.h>

#define STACKSIZE   (1024 * 1024)

static char cmd_stack[STACKSIZE];

typedef struct
{
    char    **env;
    int     fds[2];
} isolated_t;

static void die(const char *fmt, ...)
{
    va_list params;

    va_start(params, fmt);
    vfprintf(stderr, fmt, params);
    va_end(params);
    exit(1);
}

static void write_file(char path[100], char line[100])
{
    FILE *f = fopen(path, "w");

    if (f == NULL)
        die("Failed to open file %s: %m\n", path);

    if (fwrite(line, 1, strlen(line), f) < 0)
        die("Failed to write to file %s:\n", path);

    if (fclose(f) != 0)
        die("Failed to close file %s: %m\n", path);
}

static void await_setup(int pipe)
{
    char buf[2];

    if (read(pipe, buf, 2) != 2)
        die("Failed to read from pipe: %m\n");
}

static void prepare_userns(int pid)
{
    char path[100];
    char line[100];
    int uid = 1000;

    sprintf(path, "/proc/%d/uid_map", pid);
    sprintf(line, "1000 %d 1\n", uid);
    write_file(path, line);

    sprintf(path, "/proc/%d/setgroups", pid);
    sprintf(line, "deny");
    write_file(path, line);

    sprintf(path, "/proc/%d/gid_map", pid);
    sprintf(line, "1000 %d 1\n", uid);
    write_file(path, line);
}

static void prepare_mntns(char *rootfs)
{
    if (mount(rootfs, rootfs, "ext4", MS_BIND, ""))
        die("Failed to mount %s: %m\n", rootfs);

    if (chdir(rootfs))
        die("Failed to chdir to rootfs mounted at %s: %m\n", rootfs);

    if (mount("/lib/x86_64-linux-gnu", "lib/x86_64-linux-gnu", "ext4", MS_BIND | MS_REC, ""))
        die("Failed to mount /lib/x86_64-linux-gnu at %s: %m\n", rootfs);

    if (syscall(SYS_pivot_root, ".", "."))
        die("Failed to pivot_root to %s: %m\n", rootfs);

    if (mount("proc", "/proc", "proc", 0, ""))
        die("Failed to mount proc: %m\n");

    if (umount2(".", MNT_DETACH))
        die("Failed to unmount rootfs: %m\n");
}

static int cmd_exec(void *arg)
{
    isolated_t *isolated = (isolated_t*)arg;

    // Kill the cmd process if the isolate process dies.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL))
        die("cannot PR_SET_PDEATHSIG for child process: %m\n");

    // Wait for 'setup done' signal from the main process.
    await_setup(isolated->fds[0]);

    // Mount user home directory.
    prepare_mntns("box");

    // Assuming, 0 in the current namespace maps to
    // a non-privileged UID in the parent namespace,
    // drop superuser privileges if any by enforcing
    // the exec'ed process runs with UID 0.
    if (setgid(1000) == -1)
        die("Failed to setgid: %m\n");

    if (setuid(1000) == -1)
        die("Failed to setuid: %m\n");

    if (execvpe("/bin/zsh", (char*[]){ "/bin/zsh", NULL }, isolated->env) == -1)
        die("Failed to exec user shell: %m\n");

    die("NOOOOW !");
    return (1);
}

int main(int argc, char **argv, char **env)
{
    isolated_t isolated = {
        .env = env,
        .fds = { 0 }
    };

    // Set root permission.
    if (setgid(0) == -1)
        die("Failed to setgid: %m\n");

    if (setuid(0) == -1)
        die("Failed to setuid: %m\n");

    // Create pipe to communicate between main and command process.
    if (pipe(isolated.fds) < 0)
        die("Failed to create pipe: %m");

    // Clone command process.
    int clone_flags =
            // if the command process exits, it leaves an exit status
            // so that we can reap it.
            SIGCHLD |
            CLONE_NEWUTS | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID;

    int cmd_pid = clone(cmd_exec, cmd_stack + STACKSIZE, clone_flags, &isolated);

    if (cmd_pid < 0)
        die("Failed to clone: %m\n");

    // Get the writable end of the pipe.
    int pipe = isolated.fds[1];

    // Some namespace setup will take place here ...
    prepare_userns(cmd_pid);

    // Signal to the command process we're done with setup.
    if (write(pipe, "OK", 2) != 2)
        die("Failed to write to pipe: %m");

    if (close(pipe))
        die("Failed to close pipe: %m");

    if (waitpid(cmd_pid, NULL, 0) == -1)
        die("Failed to wait pid %d: %m\n", cmd_pid);

    return (0);
}
