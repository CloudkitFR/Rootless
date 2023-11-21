#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pty.h>
#include <sys/mount.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <wait.h>
#include <memory.h>
#include <syscall.h>
#include <errno.h>
#include <grp.h>
#include <fcntl.h>
#include <pwd.h>

#define STACKSIZE   (1024 * 1024)





#include <termios.h>

static struct termios save;

static void term_restore(void)
{
    // Set terminal attributes.
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &save);
}

static int term_set_raw(void)
{
    struct termios term;

    // Get terminal attributes.
    if (tcgetattr(STDIN_FILENO, &term) == -1)
        return (1);

    // Save term.
    save = term;

    // Disable echo.
    term.c_iflag        &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    term.c_oflag        &= ~(OPOST);
    term.c_cflag        |=  (CS8);
    term.c_lflag        &= ~(ECHO | ICANON | IEXTEN | ISIG);
    term.c_cc[VMIN]     = 0;
    term.c_cc[VTIME]    = 1;

    // Set terminal attributes.
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
        return (1);

    return (0);
}





#include <sys/epoll.h>
#include <sys/signalfd.h>

typedef struct poll_t poll_t;
typedef void (*poll_cb_t)(int fd, uint32_t events, poll_t *poll);

struct poll_t
{
    poll_cb_t   cb;
    void        *data;
    int         fd;
};

int poll_create(poll_t *poll)
{
    return ((poll->fd = epoll_create1(0)) == -1);
}

int poll_add(poll_t *poll, int fd, uint32_t events)
{
    return ((epoll_ctl(poll->fd, EPOLL_CTL_ADD, fd, &(struct epoll_event){
        .events     = events,
        .data.fd    = fd
    })) == -1);
}

int poll_mod(poll_t *poll, int fd, uint32_t events)
{
    return ((epoll_ctl(poll->fd, EPOLL_CTL_MOD, fd, &(struct epoll_event){
        .events     = events,
        .data.fd    = fd
    })) == -1);
}

int poll_del(poll_t *poll, int fd)
{
    return ((epoll_ctl(poll->fd, EPOLL_CTL_DEL, fd, NULL)) == -1);
}

int poll_wait(poll_t *poll, size_t max)
{
    struct epoll_event events[max];
    int count = epoll_wait(poll->fd, events, max, -1);

    // Check if epoll returned prematurely.
    if (count == -1)
        return (1);

    // Process the events.
    for (int i = 0; i < count; i++)
        poll->cb(events[i].data.fd, events[i].events, poll);

    return (0);
}



static void on_poll(int fd, uint32_t events, poll_t *poll)
{
    char    buf[2048];
    size_t  len = read(fd, buf, 2048);

    // Set null byte.
    buf[len] = 0;

    if (fd == STDIN_FILENO) {
        write(5, buf, len);

    } else {
        write(STDOUT_FILENO, buf, len);
    }
}

static char cmd_stack[STACKSIZE];

typedef struct
{
    int     fds[2];
} isolated_t;

void die(const char *fmt, ...)
{
    va_list params;

    va_start(params, fmt);
    vfprintf(stderr, fmt, params);
    va_end(params);
    exit(1);
}

void write_file(char path[100], char line[100])
{
    FILE *f = fopen(path, "w");

    if (f == NULL)
        die("Failed to open file %s: %m\n", path);

    if (fwrite(line, 1, strlen(line), f) < 0)
        die("Failed to write to file %s:\n", path);

    if (fclose(f) != 0)
        die("Failed to close file %s: %m\n", path);
}

void await_setup(int pipe)
{
    char buf[2];

    if (read(pipe, buf, 2) != 2)
        die("Failed to read from pipe: %m\n");
}

// https://github.com/moby/moby/blob/f6784595930d75bba835d4358ff9f4c7b9431636/profiles/seccomp/default_linux.go#L698
void drop_and_grant_capabilities(void) {
    cap_t caps = cap_init();

    if (!caps) {
        perror("cap_init");
        exit(EXIT_FAILURE);
    }

    // Clear all capabilities.
    if (cap_clear(caps) == -1) {
        perror("cap_clear");
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    // Grant specific capabilities.
    cap_value_t cap_values[] = {
        CAP_CHOWN,
        CAP_DAC_OVERRIDE,
        CAP_FSETID,
        CAP_FOWNER,
        CAP_MKNOD,
        CAP_NET_RAW,
        CAP_SETGID,
        CAP_SETUID,
        CAP_SETFCAP,
        CAP_SETPCAP,
        CAP_NET_BIND_SERVICE,
        CAP_SYS_CHROOT,
        CAP_KILL,
        CAP_AUDIT_WRITE
    };

    // Set the effective, inheritable, and permitted sets with the specified capabilities.
    if (cap_set_flag(caps, CAP_EFFECTIVE, sizeof(cap_values) / sizeof(cap_values[0]), cap_values, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_INHERITABLE, sizeof(cap_values) / sizeof(cap_values[0]), cap_values, CAP_SET) == -1 ||
        cap_set_flag(caps, CAP_PERMITTED, sizeof(cap_values) / sizeof(cap_values[0]), cap_values, CAP_SET) == -1) {
        perror("cap_set_flag");
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    // Apply the modified capability set to the process.
    if (cap_set_proc(caps) == -1) {
        perror("cap_set_proc");
        cap_free(caps);
        exit(EXIT_FAILURE);
    }

    cap_free(caps);
}

void prepare_userns(int pid)
{
    char path[100];

    sprintf(path, "/proc/%d/uid_map", pid);
    write_file(path, "0 0 4294967295\n");

    sprintf(path, "/proc/%d/setgroups", pid);
    write_file(path, "allow");

    sprintf(path, "/proc/%d/gid_map", pid);
    write_file(path, "0 0 4294967295\n");

    // allow unprivileged ICMP echo sockets without CAP_NET_RAW
    sprintf(path, "/proc/sys/net/ipv4/ping_group_range", pid);
    write_file(path, "0 2147483647\n");

    // allow opening any port less than 1024 without CAP_NET_BIND_SERVICE
    sprintf(path, "/proc/sys/net/ipv4/ip_unprivileged_port_start", pid);
    // set first unprivileged port to 0 so no one will be able to open a new port without CAP_NET_BIND_SERVICE.
    write_file(path, "0\n");
}

void prepare_mntns(char *rootfs)
{
    if (mount(rootfs, rootfs, "btrfs", MS_BIND, NULL))
        die("Failed to mount %s: %m\n", rootfs);

    if (chdir(rootfs))
        die("Failed to chdir to rootfs mounted at %s: %m\n", rootfs);

    // We can't mount sysfs from the user namespace, we need to bind it from the parent.
    if (mount("/sys", "sys", NULL, MS_BIND | MS_REC, NULL) != 0)
        die("Failed to mount sysfs at %s: %m\n", rootfs);

    if (syscall(SYS_pivot_root, ".", "."))
        die("Failed to pivot_root to %s: %m\n", rootfs);

    if (mount("proc", "/proc", "proc", 0, NULL))
        die("Failed to mount proc: %m\n");

    // @TODO: Setup tmpfs for /dev ?

    if (mount("devpts", "/dev/pts", "devpts", 0, "gid=0,mode=620"))
        die("Failed to mount devpts: %m\n");

    if (mount("tmpfs", "/dev/shm", "tmpfs", 0, NULL))
        die("Failed to mount shm: %m\n");

    if (umount2(".", MNT_DETACH))
        die("Failed to unmount rootfs: %m\n");
}

static int cmd_exec(void *arg)
{
    isolated_t *isolated = (isolated_t*)arg;

    //  # SETUP WAIT

    // Kill the CMD process if the isolate process die.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL))
        die("cannot PR_SET_PDEATHSIG for child process: %m\n");

    // Wait for 'setup done' signal from the main process.
    await_setup(isolated->fds[0]);

    // Mount user home directory.
    prepare_mntns("/opt/alphabet/Rootless/box");

    // # PRIVILEGES

    int master;
    int slave;

    // Open a pseudoterminal (pty) pair
    if (openpty(&master, &slave, NULL, NULL, NULL) == -1) {
        perror("openpty");
        exit(EXIT_FAILURE);
    }

    if (fork() == 0) {

        // Kill the child process if the parent process die.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL))
            die("cannot PR_SET_PDEATHSIG for child process: %m\n");

        // Assuming, 0 in the current namespace maps to
        // a non-privileged UID in the parent namespace,
        // drop superuser privileges if any by enforcing
        // the exec'ed process runs with UID 0.
        if (setuid(0) == -1 || setgid(0) == -1)
            die("Failed to setgid: %m\n");

        // Create a new session and detach from the controlling terminal
        if (setsid() == -1)
            die("Failed to setsid: %m\n");

        // https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
        // Prevent children (execve) from gaining new privileges.
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            die("i don't know what is this but seem cool");

        // Drop system capabilities.
        drop_and_grant_capabilities();

        // https://github.com/moby/moby/blob/f6784595930d75bba835d4358ff9f4c7b9431636/profiles/apparmor/template.go
        // @TODO: Create an app armor profile.
        // @TODO: Create a seccomp profile.

        // Close master.
        close(master);

        // Set the pty as IO.
        if (dup2(slave, STDIN_FILENO) == -1)
            die("Failed to dup2 STDIN: %m\n");

        if (dup2(slave, STDOUT_FILENO) == -1)
            die("Failed to dup2 STDOUT: %m\n");

        if (dup2(slave, STDERR_FILENO) == -1)
            die("Failed to dup2 STDERR: %m\n");

        // Start a new shell.
        if (execvpe(
            "/bin/zsh",
            (char*[]){ "/bin/zsh", NULL },
            (char*[]){ "USER=root", "HOME=/root", "SHELL=/bin/zsh", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", NULL }) == -1)
            die("Failed to exec user shell: %m\n");

    } else {
        poll_t poll = (poll_t){ on_poll, NULL, 0 };

        // Create epoll.
        if (poll_create(&poll))
            return (1);

        // Add pty descriptor.
        if (poll_add(&poll, master, EPOLLIN))
            return (1);

        // Add stdin descriptor.
        if (poll_add(&poll, STDIN_FILENO, EPOLLIN))
            return (1);

        // Run indefinitely.
        while (1)
            poll_wait(&poll, 16);
    }

    die("NOOOO !");
    return (1);
}

int main(int argc, char **argv)
{
    isolated_t isolated = { 0 };

    // Set raw terminal.
    if (term_set_raw())
        return (1);

    // Create pipe to communicate between main and command process.
    if (pipe(isolated.fds) < 0)
        die("Failed to create pipe: %m");

    // Clone command process.
    int clone_flags =
            // if the command process exits, it leaves an exit status
            // so that we can reap it.
            SIGCHLD
            | CLONE_NEWIPC
            | CLONE_NEWUTS
            | CLONE_NEWCGROUP
            | CLONE_NEWUSER
            | CLONE_NEWNS
            | CLONE_NEWPID;

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

    // Restore terminal.
    term_restore();

    return (0);
}
