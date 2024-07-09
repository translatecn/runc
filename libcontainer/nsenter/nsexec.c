
#define _GNU_SOURCE

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/limits.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Get all of the CLONE_NEW* flags. */
#include "namespace.h"

extern char *escape_json_string(char *str);

/* Synchronisation values. */
enum sync_t {
    SYNC_USERMAP_PLS = 0x40,      /* Request parent to map our users. */
    SYNC_USERMAP_ACK = 0x41,      /* Mapping finished by the parent. */
    SYNC_RECVPID_PLS = 0x42,      /* Tell parent we're sending the PID. */
    SYNC_RECVPID_ACK = 0x43,      /* PID was correctly received by parent. */
    SYNC_GRANDCHILD = 0x44,       /* The grandchild is ready to run. */
    SYNC_CHILD_FINISH = 0x45,     /* The child or grandchild has finished. */
    SYNC_MOUNTSOURCES_PLS = 0x46, /* Tell parent to send mount sources by SCM_RIGHTS. */
    SYNC_MOUNTSOURCES_ACK = 0x47, /* All mount sources have been sent. */
};

#define STAGE_SETUP -1
/* longjmp() arguments. */
#define STAGE_PARENT 0
#define STAGE_CHILD 1
#define STAGE_INIT 2

/* Stores the current stage of nsexec. */
int current_stage = STAGE_SETUP;

/* Assume the stack grows down, so arguments should be above it. */
struct clone_t {
    /*
     * Reserve some space for clone() to locate arguments
     * and retcode in this place
     */
    char stack[4096] __attribute__((aligned(16)));
    char stack_ptr[0];

    /* There's two children. This is used to execute the different code. */
    jmp_buf *env;
    int jmpval;
};

struct nlconfig_t {
    char *data;

    /* Process settings. */
    uint32_t cloneflags;
    char *oom_score_adj;
    size_t oom_score_adj_len;

    /* User namespace settings. */
    char *uidmap;
    size_t uidmap_len;
    char *gidmap;
    size_t gidmap_len;
    char *namespaces;
    size_t namespaces_len;
    uint8_t is_setgroup;

    /* Rootless container settings. */
    uint8_t is_rootless_euid; /* boolean */
    char *uidmappath;         // 二进制文件的路径
    size_t uidmappath_len;
    char *gidmappath; // 二进制文件的路径
    size_t gidmappath_len;

    /* Mount sources opened outside the container userns. */
    char *mountsources;
    size_t mountsources_len;
};

/*
 * Log levels are the same as in logrus.
 */
#define PANIC 0
#define FATAL 1
#define ERROR 2
#define WARNING 3
#define INFO 4
#define DEBUG 5
#define TRACE 6

static const char *level_str[] = {"panic", "fatal", "error", "warning", "info", "debug", "trace"};

static int logfd = -1;       // NewSockPair      init-c    3 child
static int loglevel = DEBUG; // os.Pipe()        |1        4

/*
 * List of netlink message types sent to us as part of bootstrapping the init.
 * These constants are defined in libcontainer/message_linux.go.
 */
#define INIT_MSG 62000
#define CLONE_FLAGS_ATTR 27281
#define NS_PATHS_ATTR 27282
#define UIDMAP_ATTR 27283
#define GIDMAP_ATTR 27284
#define SETGROUP_ATTR 27285
#define OOM_SCORE_ADJ_ATTR 27286
#define ROOTLESS_EUID_ATTR 27287
#define UIDMAPPATH_ATTR 27288
#define GIDMAPPATH_ATTR 27289
#define MOUNT_SOURCES_ATTR 27290

/*
 * Use the raw syscall for versions of glibc which don't include a function for
 * it, namely (glibc 2.12).
 */
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
#    define _GNU_SOURCE
#    include "syscall.h"
#    if !defined(SYS_setns) && defined(__NR_setns)
#        define SYS_setns __NR_setns
#    endif

#    ifndef SYS_setns
#        error "setns(2) syscall not supported by glibc version"
#    endif

int setns(int fd, int nstype) {
    return syscall(SYS_setns, fd, nstype);
}
#endif

static void write_log(int level, const char *format, ...) {
    char *message = NULL, *stage = NULL, *json = NULL;
    va_list args;
    int ret;

    if (logfd < 0 || level > loglevel)
        goto out;

    va_start(args, format);
    ret = vasprintf(&message, format, args);
    va_end(args);
    if (ret < 0) {
        message = NULL;
        goto out;
    }

    message = escape_json_string(message);

    if (current_stage == STAGE_SETUP) {
        stage = strdup("nsexec");
        if (stage == NULL)
            goto out;
    }
    else {
        ret = asprintf(&stage, "nsexec-%d", current_stage);
        if (ret < 0) {
            stage = NULL;
            goto out;
        }
    }
    ret = asprintf(&json, "{\"level\":\"%s\", \"msg\": \"%s[%d]: %s\"}\n", level_str[level], stage, getpid(), message);
    if (ret < 0) {
        json = NULL;
        goto out;
    }

    /* This logging is on a best-effort basis. In case of a short or failed
     * write there is nothing we can do, so just ignore write() errors.
     */
    ssize_t __attribute__((unused)) __res = write(logfd, json, ret);

out:
    free(message);
    free(stage);
    free(json);
}

/* XXX: This is ugly. */
static int syncfd = -1;

#define bail(fmt, ...)                                              \
    do {                                                            \
        if (logfd < 0)                                              \
            fprintf(stderr, "FATAL: " fmt ": %m\n", ##__VA_ARGS__); \
        else                                                        \
            write_log(FATAL, fmt ": %m", ##__VA_ARGS__);            \
        exit(1);                                                    \
    } while (0)

static int write_file(char *data, size_t data_len, char *pathfmt, ...) {
    int fd, len, ret = 0;
    char path[PATH_MAX];

    va_list ap;
    va_start(ap, pathfmt);
    len = vsnprintf(path, PATH_MAX, pathfmt, ap);
    va_end(ap);
    if (len < 0)
        return -1;

    fd = open(path, O_RDWR);
    if (fd < 0) {
        return -1;
    }

    len = write(fd, data, data_len);
    if (len != data_len) {
        ret = -1;
        goto out;
    }

out:
    close(fd);
    return ret;
}

static int getenv_int(const char *name) {
    char *val, *endptr;
    int ret;

    val = getenv(name);
    /* Treat empty value as unset variable. */
    if (val == NULL || *val == '\0')
        return -ENOENT; // -2

    ret = strtol(val, &endptr, 10);
    if (val == endptr || *endptr != '\0')
        bail("unable to parse %s=%s", name, val);
    /*
     * Sanity check: this must be a non-negative number.
     */
    if (ret < 0)
        bail("bad value for %s=%s (%d)", name, val, ret);

    return ret;
}

static void setup_logpipe(void) {
    int i;

    i = getenv_int("_LIBCONTAINER_LOGPIPE"); // NewSockPair      init-c    3 child
    if (i < 0) {
        /* We are not runc init, or log pipe was not provided. */
        return;
    }
    logfd = i;

    i = getenv_int("_LIBCONTAINER_LOGLEVEL"); // os.Pipe()        |1        4
    if (i < 0)
        return;
    loglevel = i;
}

enum policy_t {
    SETGROUPS_DEFAULT = 0,
    SETGROUPS_ALLOW,
    SETGROUPS_DENY,
};

/* This *must* be called before we touch gid_map. */
static void update_setgroups(int pid, enum policy_t setgroup) {
    char *policy;

    switch (setgroup) {
        case SETGROUPS_ALLOW:
            policy = "allow";
            break;
        case SETGROUPS_DENY:
            policy = "deny";
            break;
        case SETGROUPS_DEFAULT:
        default:
            /* Nothing to do. */
            return;
    }

    if (write_file(policy, strlen(policy), "/proc/%d/setgroups", pid) < 0) {
        /*
         * If the kernel is too old to support /proc/pid/setgroups,
         * open(2) or write(2) will return ENOENT. This is fine.
         */
        if (errno != ENOENT)
            bail("failed to write '%s' to /proc/%d/setgroups", policy, pid);
    }
}

// ✅✅✅✅✅✅✅✅
static int try_mapping_tool(const char *binpath, int pid, char *map, size_t map_len) {
    int child;

    /*
     * If @app is NULL, execve will segfault. Just check it here and bail (if
     * we're in this path, the caller is already getting desperate and there
     * isn't a backup to this failing). This usually would be a configuration
     * or programming issue.
     */
    if (!binpath)
        bail("mapping tool not present");

    child = fork();
    if (child < 0)
        bail("failed to fork");

    if (!child) {
        // 子进程
#define MAX_ARGV 20
        char *argv[MAX_ARGV];
        char *envp[] = {NULL};
        char pid_fmt[16];
        int argc = 0;
        char *next;

        snprintf(pid_fmt, 16, "%d", pid);

        argv[argc++] = (char *)binpath;
        argv[argc++] = pid_fmt;
        // newuidmap $(pidof runc:[1:CHILD]) ContainerID_0 ContainerID_1

        //        fmt.Sprintf("%d %d %d\n", im.ContainerID, im.HostID, im.Size)
        while (argc < MAX_ARGV) {
            if (*map == '\0') {
                argv[argc++] = NULL;
                break;
            }
            argv[argc++] = map;
            next = strpbrk(map, "\n ");
            if (next == NULL)
                break;
            *next++ = '\0';
            map = next + strspn(next, "\n "); // 获取的 ContainerID
        }

        execve(binpath, argv, envp);
        bail("failed to execv");
    }
    else {
        // 当进程
        int status;

        while (true) {
            if (waitpid(child, &status, 0) < 0) {
                if (errno == EINTR)
                    continue;
                bail("failed to waitpid");
            }
            if (WIFEXITED(status) || WIFSIGNALED(status))
                return WEXITSTATUS(status);
        }
    }

    return -1;
}

// ✅✅✅✅✅✅✅✅
static void update_uidmap(const char *binpath, int pid, char *map, size_t map_len) {
    if (map == NULL || map_len == 0)
        return;

    write_log(DEBUG, "update /proc/%d/uid_map to '%s'", pid, map);
    if (write_file(map, map_len, "/proc/%d/uid_map", pid) < 0) {
        if (errno != EPERM)
            bail("failed to update /proc/%d/uid_map", pid);
        write_log(DEBUG, "update /proc/%d/uid_map got -EPERM (trying %s)", pid, binpath);
        if (try_mapping_tool(binpath, pid, map, map_len))
            bail("failed to use newuid map on %d", pid);
    }
}

// ✅✅✅✅✅✅✅✅
static void update_gidmap(const char *path, int pid, char *map, size_t map_len) {
    if (map == NULL || map_len == 0)
        return;

    write_log(DEBUG, "update /proc/%d/gid_map to '%s'", pid, map);
    if (write_file(map, map_len, "/proc/%d/gid_map", pid) < 0) {
        if (errno != EPERM)
            bail("failed to update /proc/%d/gid_map", pid);
        write_log(DEBUG, "update /proc/%d/gid_map got -EPERM (trying %s)", pid, path);
        if (try_mapping_tool(path, pid, map, map_len))
            bail("failed to use newgid map on %d", pid);
    }
}

// ✅✅✅✅✅✅✅✅
static void update_oom_score_adj(char *data, size_t len) {
    if (data == NULL || len == 0)
        return;

    write_log(DEBUG, "update /proc/self/oom_score_adj to '%s'", data);
    if (write_file(data, len, "/proc/self/oom_score_adj") < 0)
        bail("failed to update /proc/self/oom_score_adj");
}

/* A dummy function that just jumps to the given jumpval. */
static int child_func(void *arg) __attribute__((noinline));

static int child_func(void *arg) {
    struct clone_t *ca = (struct clone_t *)arg;
    longjmp(*ca->env, ca->jmpval);
}

static int clone_parent(jmp_buf *env, int jmpval) __attribute__((noinline));

static int clone_parent(jmp_buf *env, int jmpval) {
    struct clone_t ca = {
        .env = env,
        .jmpval = jmpval,
    };
    //    clone 函数它主要用于创建新的进程（也包括线程，因为线程是“特殊”的进程），调用成功后，返回子进程的 tid，如果失败，则返回 -1，并将错误码设置再 errno。
    //    clone 函数的第1个参数fn是一个函数指针；第2个参数child_stack是用于创建子进程的栈(注意需要将栈的高地址传入）；第3个参数flags，就是用于指定行为的参数了。
    //    CLONE_PARENT:创建的子进程的父进程是调用者的父进程，新进程与创建它的进程成了“兄弟”而不是“父子”
    //    SIGCHLD: 信号是在子进程终止或停止时由操作系统发送给父进程的信号
    return clone(child_func, ca.stack_ptr, CLONE_PARENT | SIGCHLD, &ca);
}
// ✅✅✅✅✅✅✅✅
/* Returns the clone(2) flag for a namespace, given the name of a namespace. */
static int nsflag(char *name) {
    if (!strcmp(name, "cgroup"))
        return CLONE_NEWCGROUP;
    else if (!strcmp(name, "ipc"))
        return CLONE_NEWIPC;
    else if (!strcmp(name, "mnt"))
        return CLONE_NEWNS;
    else if (!strcmp(name, "net"))
        return CLONE_NEWNET;
    else if (!strcmp(name, "pid"))
        return CLONE_NEWPID;
    else if (!strcmp(name, "user"))
        return CLONE_NEWUSER;
    else if (!strcmp(name, "uts"))
        return CLONE_NEWUTS;

    /* If we don't recognise a name, fallback to 0. */
    return 0;
}

static uint32_t readint32(char *buf) {
    return *(uint32_t *)buf;
}

static uint8_t readint8(char *buf) {
    return *(uint8_t *)buf;
}

// ✅✅✅✅✅✅✅✅
static void nl_parse(int fd, struct nlconfig_t *config) {
    size_t len, size;
    struct nlmsghdr hdr;
    char *data, *current;

    /* Retrieve the netlink header. */
    len = read(fd, &hdr, NLMSG_HDRLEN);
    if (len != NLMSG_HDRLEN)
        bail("invalid netlink header length %zu", len);

    if (hdr.nlmsg_type == NLMSG_ERROR)
        bail("failed to read netlink message");

    if (hdr.nlmsg_type != INIT_MSG)
        bail("unexpected msg type %d", hdr.nlmsg_type);

    /* Retrieve data. */
    size = NLMSG_PAYLOAD(&hdr, 0);
    current = data = malloc(size);
    if (!data)
        bail("failed to allocate %zu bytes of memory for nl_payload", size);

    len = read(fd, data, size);
    if (len != size)
        bail("failed to read netlink payload, %zu != %zu", len, size);

    /* Parse the netlink payload. */
    config->data = data;
    while (current < data + size) {
        struct nlattr *nlattr = (struct nlattr *)current;
        size_t payload_len = nlattr->nla_len - NLA_HDRLEN;

        /* Advance to payload. */
        current += NLA_HDRLEN;

        /* Handle payload. */
        switch (nlattr->nla_type) {
            case CLONE_FLAGS_ATTR:
                config->cloneflags = readint32(current);
                break;
            case ROOTLESS_EUID_ATTR:
                config->is_rootless_euid = readint8(current); /* boolean */
                break;
            case OOM_SCORE_ADJ_ATTR:
                config->oom_score_adj = current;
                config->oom_score_adj_len = payload_len;
                break;
            case NS_PATHS_ATTR:
                config->namespaces = current;
                config->namespaces_len = payload_len;
                break;
            case UIDMAP_ATTR:
                config->uidmap = current;
                config->uidmap_len = payload_len;
                break;
            case GIDMAP_ATTR:
                config->gidmap = current;
                config->gidmap_len = payload_len;
                break;
            case UIDMAPPATH_ATTR:
                config->uidmappath = current;
                config->uidmappath_len = payload_len;
                break;
            case GIDMAPPATH_ATTR:
                config->gidmappath = current;
                config->gidmappath_len = payload_len;
                break;
            case SETGROUP_ATTR:
                config->is_setgroup = readint8(current);
                break;
            case MOUNT_SOURCES_ATTR:
                config->mountsources = current;
                config->mountsources_len = payload_len;
                break;
            default:
                bail("unknown netlink message type %d", nlattr->nla_type);
        }

        current += NLA_ALIGN(payload_len);
    }
}

// ✅✅✅✅✅✅✅✅
void nl_free(struct nlconfig_t *config) {
    free(config->data);
}

// ✅✅✅✅✅✅✅✅
void join_namespaces(char *nslist) {
    int num = 0, i;
    char *saveptr = NULL;
    char *namespace = strtok_r(nslist, ",", &saveptr);
    struct namespace_t {
        int fd;
        char type[PATH_MAX];
        char path[PATH_MAX];
    } *namespaces = NULL;

    if (!namespace || !strlen(namespace) || !strlen(nslist))
        bail("ns paths are empty");

    /*
     * We have to open the file descriptors first, since after
     * we join the mnt namespace we might no longer be able to
     * access the paths.
     */
    do {
        int fd;
        char *path;
        struct namespace_t *ns;

        /* Resize the namespace array. */
        namespaces = realloc(namespaces, ++num * sizeof(struct namespace_t));
        if (!namespaces)
            bail("failed to reallocate namespace array");
        ns = &namespaces[num - 1];

        /* Split 'ns:path'. */
        path = strstr(namespace, ":");
        if (!path)
            bail("failed to parse %s", namespace);
        *path++ = '\0';

        fd = open(path, O_RDONLY);
        if (fd < 0)
            bail("failed to open %s", path);

        ns->fd = fd;
        strncpy(ns->type, namespace, PATH_MAX - 1);
        strncpy(ns->path, path, PATH_MAX - 1);
        ns->path[PATH_MAX - 1] = '\0';
    } while ((namespace = strtok_r(NULL, ",", &saveptr)) != NULL);

    /*
     * The ordering in which we join namespaces is important. We should
     * always join the user namespace *first*. This is all guaranteed
     * from the container_linux.go side of this, so we're just going to
     * follow the order given to us.
     */

    for (i = 0; i < num; i++) {
        struct namespace_t *ns = &namespaces[i];
        int flag = nsflag(ns->type);

        write_log(DEBUG, "setns(%#x) into %s namespace (with path %s)", flag, ns->type, ns->path);
        if (setns(ns->fd, flag) < 0) {
            // 当前进程的 的  flag 加入到这个 ns->fd名称空间
            bail("failed to setns into %s namespace", ns->type);
        }
        close(ns->fd);
    }

    free(namespaces);
}

/* Defined in cloned_binary.c. */
extern int ensure_cloned_binary(void);

static inline int sane_kill(pid_t pid, int signum) {
    if (pid > 0)
        return kill(pid, signum);
    else
        return 0;
}

void receive_fd(int sockfd, int new_fd) {
    int bytes_read;
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    struct iovec iov = {};
    char null_byte = '\0';
    int ret;
    int fd_count;
    int *fd_payload;

    iov.iov_base = &null_byte;
    iov.iov_len = 1;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    msg.msg_control = malloc(msg.msg_controllen);
    if (msg.msg_control == NULL) {
        bail("Can't allocate memory to receive fd.");
    }

    memset(msg.msg_control, 0, msg.msg_controllen);

    bytes_read = recvmsg(sockfd, &msg, 0);
    if (bytes_read != 1)
        bail("failed to receive fd from unix socket %d", sockfd);
    if (msg.msg_flags & MSG_CTRUNC)
        bail("received truncated control message from unix socket %d", sockfd);

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
        bail("received message from unix socket %d without control message", sockfd);

    if (cmsg->cmsg_level != SOL_SOCKET)
        bail("received unknown control message from unix socket %d: cmsg_level=%d", sockfd, cmsg->cmsg_level);

    if (cmsg->cmsg_type != SCM_RIGHTS)
        bail("received unknown control message from unix socket %d: cmsg_type=%d", sockfd, cmsg->cmsg_type);

    fd_count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    if (fd_count != 1)
        bail("received control message from unix socket %d with too many fds: %d", sockfd, fd_count);

    fd_payload = (int *)CMSG_DATA(cmsg);
    ret = dup3(*fd_payload, new_fd, O_CLOEXEC);
    if (ret < 0)
        bail("cannot dup3 fd %d to %d", *fd_payload, new_fd);

    free(msg.msg_control);

    ret = close(*fd_payload);
    if (ret < 0)
        bail("cannot close fd %d", *fd_payload);
}

// ✅✅✅✅✅✅✅✅
void send_fd(int sockfd, int fd) {
    int bytes_written;
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    struct iovec iov[1] = {};
    char null_byte = '\0';

    iov[0].iov_base = &null_byte;
    iov[0].iov_len = 1;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    /* We send only one fd as specified by cmsg->cmsg_len below, even
     * though msg.msg_controllen might have more space due to alignment. */
    msg.msg_controllen = CMSG_SPACE(sizeof(int));
    msg.msg_control = malloc(msg.msg_controllen);
    if (msg.msg_control == NULL) {
        bail("Can't allocate memory to send fd.");
    }

    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    bytes_written = sendmsg(sockfd, &msg, 0);

    free(msg.msg_control);

    if (bytes_written != 1)
        bail("failed to send fd %d via unix socket %d", fd, sockfd);
}

void receive_mountsources(int sockfd) {
    char *mount_fds, *endp;
    long new_fd;

    // This env var must be a json array of ints.
    mount_fds = getenv("_LIBCONTAINER_MOUNT_FDS");

    if (mount_fds[0] != '[') {
        bail("malformed _LIBCONTAINER_MOUNT_FDS env var: missing '['");
    }
    mount_fds++;

    for (endp = mount_fds; *endp != ']'; mount_fds = endp + 1) {
        new_fd = strtol(mount_fds, &endp, 10);
        if (endp == mount_fds) {
            bail("malformed _LIBCONTAINER_MOUNT_FDS env var: not a number");
        }
        if (*endp == '\0') {
            bail("malformed _LIBCONTAINER_MOUNT_FDS env var: missing ]");
        }
        // The list contains -1 when no fd is needed. Ignore them.
        if (new_fd == -1) {
            continue;
        }

        if (new_fd == LONG_MAX || new_fd < 0 || new_fd > INT_MAX) {
            bail("malformed _LIBCONTAINER_MOUNT_FDS env var: fds out of range");
        }

        receive_fd(sockfd, new_fd);
    }
}

// ✅✅✅✅✅✅✅✅
void send_mountsources(int sockfd, pid_t child, char *mountsources, size_t mountsources_len) {
    char proc_path[PATH_MAX];
    int host_mntns_fd;
    int container_mntns_fd;
    int fd;
    int ret;

    // container_linux.go shouldSendMountSources() decides if mount sources
    // should be pre-opened (O_PATH) and passed via SCM_RIGHTS
    if (mountsources == NULL)
        return;

    host_mntns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (host_mntns_fd == -1)
        bail("failed to get current mount namespace");

    if (snprintf(proc_path, PATH_MAX, "/proc/%d/ns/mnt", child) < 0) // runc:[0:PARENT]
        bail("failed to get mount namespace path");

    container_mntns_fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    if (container_mntns_fd == -1)
        bail("failed to get container mount namespace");

    if (setns(container_mntns_fd, CLONE_NEWNS) < 0)
        bail("failed to setns to container mntns");

    char *mountsources_end = mountsources + mountsources_len;
    while (mountsources < mountsources_end) {
        if (mountsources[0] == '\0') {
            mountsources++;
            continue;
        }

        fd = open(mountsources, O_PATH | O_CLOEXEC);
        if (fd < 0)
            bail("failed to open mount source %s", mountsources);

        send_fd(sockfd, fd);

        ret = close(fd);
        if (ret != 0)
            bail("failed to close mount source fd %d", fd);

        mountsources += strlen(mountsources) + 1;
    }

    if (setns(host_mntns_fd, CLONE_NEWNS) < 0)
        bail("failed to setns to host mntns");

    ret = close(host_mntns_fd);
    if (ret != 0)
        bail("failed to close host mount namespace fd %d", host_mntns_fd);
    ret = close(container_mntns_fd);
    if (ret != 0)
        bail("failed to close container mount namespace fd %d", container_mntns_fd);
}

void try_unshare(int flags, const char *msg) { // 创建独立的命名空间
    write_log(DEBUG, "unshare %s", msg);
    int retries = 5;
    for (; retries > 0; retries--) {
        if (unshare(flags) == 0) { // 🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆
            return;
        }
        if (errno != EINVAL)
            break;
    }
    bail("failed to unshare %s", msg);
}

void nsexec(void) {
    int pipenum;
    jmp_buf env;
    int sync_child_pipe[2], sync_grandchild_pipe[2];
    struct nlconfig_t config = {0};

    setup_logpipe(); // ✅

    pipenum = getenv_int("_LIBCONTAINER_INITPIPE"); // NewSockPair      init-c 3
    if (pipenum < 0) {                              // runc start 时没有这个环境环境，在这里会直接返回
       // fprintf(stderr, "-----------------");
        return;
    }

    if (ensure_cloned_binary() < 0) {
        bail("不能确保我们是克隆的二进制文件");
    }
    /*
     * Inform the parent we're past initial setup.
     * For the other side of this, see initWaiter.
     */
    if (write(pipenum, "", 1) != 1) // 第一次回写，对应   `} else if inited[0] != 0 {`
    {
        bail("could not inform the parent we are past initial setup");
    }

    write_log(DEBUG, "=> nsexec container setup");

    nl_parse(pipenum, &config); // 对应  ` io.Copy(p.messageSockPair.parent, p.bootstrapData)`

    update_oom_score_adj(config.oom_score_adj, config.oom_score_adj_len);

    // 使进程不可转储，以避免可能导致我们正在加入的命名空间中的进程访问主机资源(或可能执行代码)的各种竞争条件。
    // 但是，如果我们要加入的命名空间的数量是0，我们将不会切换到不同的安全上下文。因此，将我们自己设置为不可转储只会破坏一些东西(比如无根容器)，这是内核人员的建议。
    if (config.namespaces) { // 各个子系统应该创建的路径
        write_log(DEBUG, "set process as non-dumpable");
        if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
            bail("failed to set process as non-dumpable");
    }

    // 这样我们就可以告诉孩子我们什么时候布置好了。
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_child_pipe) < 0)
        bail("failed to setup sync pipe between parent and child");

    //    We need a new socketpair to sync with grandchild so we don't have race condition with child.
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sync_grandchild_pipe) < 0)
        bail("failed to setup sync pipe between parent and grandchild");

    current_stage = setjmp(env); // 设置跳转点,current_stage = longjmp(设置的值)，默认0
    switch (current_stage) {
        case STAGE_PARENT: { // 创建子进程、设置uid_map、gid_map 并返回它的pid
            int len;
            pid_t stage1_pid = -1, stage2_pid = -1;
            bool stage1_complete, stage2_complete;

            /* For debugging. */
            prctl(PR_SET_NAME, (unsigned long)"runc:[0:PARENT]", 0, 0, 0); // 设置进程名，可以top 看到
            write_log(DEBUG, "~> nsexec stage-0");

            /* Start the process of getting a container. */
            write_log(DEBUG, "spawn stage-1");
            stage1_pid = clone_parent(&env, STAGE_CHILD); // 启动一个兄弟进程执行 STAGE_CHILD 分支
            if (stage1_pid < 0)
                bail("unable to spawn stage-1");

            syncfd = sync_child_pipe[1];
            if (close(sync_child_pipe[0]) < 0)
                bail("failed to close sync_child_pipe[0] fd");

            /*
             * State machine for synchronisation with the children. We only
             * return once both the child and grandchild are ready.
             */
            write_log(DEBUG, "-> stage-1 synchronisation loop");
            stage1_complete = false;
            while (!stage1_complete) {
                enum sync_t s;

                if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                    bail("failed to sync with stage-1: next state");
                // 第一次发送 SYNC_USERMAP_PLS

                switch (s) {
                    case SYNC_USERMAP_PLS: // ✅
                        write_log(DEBUG, "stage-1 requested userns mappings");
                        if (config.is_rootless_euid && !config.is_setgroup) {
                            update_setgroups(stage1_pid, SETGROUPS_DENY);
                        }

                        /* Set up mappings. */
                        update_uidmap(config.uidmappath, stage1_pid, config.uidmap, config.uidmap_len);
                        update_gidmap(config.gidmappath, stage1_pid, config.gidmap, config.gidmap_len);

                        s = SYNC_USERMAP_ACK;
                        if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                            sane_kill(stage1_pid, SIGKILL);
                            sane_kill(stage2_pid, SIGKILL);
                            bail("failed to sync with stage-1: write(SYNC_USERMAP_ACK)");
                        }
                        break;
                    case SYNC_RECVPID_PLS:
                        write_log(DEBUG, "stage-1 requested pid to be forwarded");

                        /* Get the stage-2 pid. */
                        if (read(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
                            sane_kill(stage1_pid, SIGKILL);
                            sane_kill(stage2_pid, SIGKILL);
                            bail("failed to sync with stage-1: read(stage2_pid)");
                        }

                        /* Send ACK. */
                        s = SYNC_RECVPID_ACK;
                        if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                            sane_kill(stage1_pid, SIGKILL);
                            sane_kill(stage2_pid, SIGKILL);
                            bail("failed to sync with stage-1: write(SYNC_RECVPID_ACK)");
                        }

                        /*
                         * Send both the stage-1 and stage-2 pids back to runc.
                         * runc needs the stage-2 to continue process management,
                         * but because stage-1 was spawned with CLONE_PARENT we
                         * cannot reap it within stage-0 and thus we need to ask
                         * runc to reap the zombie for us.
                         */
                        write_log(DEBUG, "forward stage-1 (%d) and stage-2 (%d) pids to runc", stage1_pid, stage2_pid);
                        len = dprintf(pipenum, "{\"stage1_pid\":%d,\"stage2_pid\":%d}\n", stage1_pid, stage2_pid);
                        if (len < 0) {
                            sane_kill(stage1_pid, SIGKILL);
                            sane_kill(stage2_pid, SIGKILL);
                            bail("failed to sync with runc: write(pid-JSON)");
                        }
                        break;
                    case SYNC_MOUNTSOURCES_PLS: // ✅
                        send_mountsources(syncfd, stage1_pid, config.mountsources, config.mountsources_len);

                        s = SYNC_MOUNTSOURCES_ACK;
                        if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                            sane_kill(stage1_pid, SIGKILL);
                            bail("failed to sync with child: write(SYNC_MOUNTSOURCES_ACK)");
                        }
                        break;
                    case SYNC_CHILD_FINISH:
                        write_log(DEBUG, "stage-1 complete");
                        stage1_complete = true;
                        break;
                    default:
                        bail("unexpected sync value: %u", s);
                }
            }
            write_log(DEBUG, "<- stage-1 synchronisation loop");

            /* Now sync with grandchild. */
            syncfd = sync_grandchild_pipe[1];
            if (close(sync_grandchild_pipe[0]) < 0)
                bail("failed to close sync_grandchild_pipe[0] fd");

            write_log(DEBUG, "-> stage-2 synchronisation loop");
            stage2_complete = false;
            while (!stage2_complete) {
                enum sync_t s;

                write_log(DEBUG, "signalling stage-2 to run");
                s = SYNC_GRANDCHILD;
                if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                    sane_kill(stage2_pid, SIGKILL);
                    bail("failed to sync with child: write(SYNC_GRANDCHILD)");
                }

                if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                    bail("failed to sync with child: next state");

                switch (s) {
                    case SYNC_CHILD_FINISH:
                        write_log(DEBUG, "stage-2 complete");
                        stage2_complete = true;
                        break;
                    default:
                        bail("unexpected sync value: %u", s);
                }
            }
            write_log(DEBUG, "<- stage-2 synchronisation loop");
            write_log(DEBUG, "<~ nsexec stage-0");
            exit(0);
        } break;

            /*
             * Stage 1: We're in the first child process. Our job is to join any
             *          provided namespaces in the netlink payload and unshare all of
             *          the requested namespaces. If we've been asked to CLONE_NEWUSER,
             *          we will ask our parent (stage 0) to set up our user mappings
             *          for us. Then, we create a new child (stage 2: STAGE_INIT) for
             *          PID namespace. We then send the child's PID to our parent
             *          (stage 0).
             */
        case STAGE_CHILD: {
            pid_t stage2_pid = -1;
            enum sync_t s;

            /* We're in a child and thus need to tell the parent if we die. */
            syncfd = sync_child_pipe[0];
            if (close(sync_child_pipe[1]) < 0)
                bail("failed to close sync_child_pipe[1] fd");

            /* For debugging. */
            prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0);
            write_log(DEBUG, "~> nsexec stage-1");

            // 我们需要先设置命名空间。我们不能更早地这样做（在阶段0），
            // 因为事实上我们是通过fork来到这里的（[阶段2：STAGE_INIT]的PID将变得毫无意义）。
            // 我们可以使用cmsg(3)来发送它，但这确实很烦人。

            if (config.namespaces) {
                join_namespaces(config.namespaces); // setns  切换网络名称空间
            }

            if (config.cloneflags & CLONE_NEWUSER) {
                try_unshare(CLONE_NEWUSER, "user namespace");
                config.cloneflags &= ~CLONE_NEWUSER;

                if (config.namespaces) {
                    write_log(DEBUG, "temporarily set process as dumpable");
                    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0) { // 使进程可转储
                        bail("failed to temporarily set process as dumpable");
                    }
                }

                /*
                 * We don't have the privileges to do any mapping here (see the
                 * clone_parent rant). So signal stage-0 to do the mapping for
                 * us.
                 */
                write_log(DEBUG, "request stage-0 to map user namespace");
                s = SYNC_USERMAP_PLS;
                if (write(syncfd, &s, sizeof(s)) != sizeof(s))
                    bail("failed to sync with parent: write(SYNC_USERMAP_PLS)");

                /* ... wait for mapping ... */
                write_log(DEBUG, "request stage-0 to map user namespace");
                if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                    bail("failed to sync with parent: read(SYNC_USERMAP_ACK)");
                if (s != SYNC_USERMAP_ACK)
                    bail("failed to sync with parent: SYNC_USERMAP_ACK: got %u", s);

                /* Revert temporary re-dumpable setting. */
                if (config.namespaces) {
                    write_log(DEBUG, "re-set process as non-dumpable");
                    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
                        bail("failed to re-set process as non-dumpable");
                }

                //         在Linux系统中，每个进程都有三种不同的`uid`：真实用户ID（`uid`）、有效用户ID（`euid`）和保存的用户ID（`suid`）。
                //         其中，真实用户ID是指进程的实际所有者；
                //         有效用户ID是指用来控制进程权限的用户；
                //         保存的用户ID是用来备份之前的`euid`。
                if (setresuid(0, 0, 0) < 0)
                    bail("failed to become root in user namespace");
            }

            try_unshare(config.cloneflags & ~CLONE_NEWCGROUP, "remaining namespaces (except cgroupns)");

            //             ✅
            if (config.mountsources) {
                s = SYNC_MOUNTSOURCES_PLS;
                if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                    sane_kill(stage2_pid, SIGKILL);
                    bail("failed to sync with parent: write(SYNC_MOUNTSOURCES_PLS)");
                }

                /* Receive and install all mount sources fds. */
                receive_mountsources(syncfd);

                /* Parent finished to send the mount sources fds. */
                if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
                    sane_kill(stage2_pid, SIGKILL);
                    bail("failed to sync with parent: read(SYNC_MOUNTSOURCES_ACK)");
                }
                if (s != SYNC_MOUNTSOURCES_ACK) {
                    sane_kill(stage2_pid, SIGKILL);
                    bail("failed to sync with parent: SYNC_MOUNTSOURCES_ACK: got %u", s);
                }
            }

            /*
             * TODO: What about non-namespace clone flags that we're dropping here?
             *
             * We fork again because of PID namespace, setns(2) or unshare(2) don't
             * change the PID namespace of the calling process, because doing so
             * would change the caller's idea of its own PID (as reported by getpid()),
             * which would break many applications and libraries, so we must fork
             * to actually enter the new PID namespace.
             */
            write_log(DEBUG, "spawn stage-2");
            stage2_pid = clone_parent(&env, STAGE_INIT);
            if (stage2_pid < 0)
                bail("unable to spawn stage-2");

            /* Send the child to our parent, which knows what it's doing. */
            write_log(DEBUG, "request stage-0 to forward stage-2 pid (%d)", stage2_pid);
            s = SYNC_RECVPID_PLS;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
            }
            if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(stage2_pid)");
            }

            /* ... wait for parent to get the pid ... */
            if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
            }
            if (s != SYNC_RECVPID_ACK) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);
            }

            write_log(DEBUG, "signal completion to stage-0");
            s = SYNC_CHILD_FINISH;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");
            }

            /* Our work is done. [Stage 2: STAGE_INIT] is doing the rest of the work. */
            write_log(DEBUG, "<~ nsexec stage-1");
            exit(0);
        } break;

            /*
             * Stage 2: We're the final child process, and the only process that will
             *          actually return to the Go runtime. Our job is to just do the
             *          final cleanup steps and then return to the Go runtime to allow
             *          init_linux.go to run.
             */
        case STAGE_INIT: {
            /*
             * We're inside the child now, having jumped from the
             * start_child() code after forking in the parent.
             */
            enum sync_t s;

            /* We're in a child and thus need to tell the parent if we die. */
            syncfd = sync_grandchild_pipe[0];
            if (close(sync_grandchild_pipe[1]) < 0)
                bail("failed to close sync_grandchild_pipe[1] fd");

            if (close(sync_child_pipe[0]) < 0)
                bail("failed to close sync_child_pipe[0] fd");

            /* For debugging. */
            prctl(PR_SET_NAME, (unsigned long)"runc:[2:INIT]", 0, 0, 0);
            write_log(DEBUG, "~> nsexec stage-2");

            if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                bail("failed to sync with parent: read(SYNC_GRANDCHILD)");
            if (s != SYNC_GRANDCHILD)
                bail("failed to sync with parent: SYNC_GRANDCHILD: got %u", s);

            if (setsid() < 0)
                bail("setsid failed");

            if (setuid(0) < 0)
                bail("setuid failed");

            if (setgid(0) < 0)
                bail("setgid failed");

            if (!config.is_rootless_euid && config.is_setgroup) {
                if (setgroups(0, NULL) < 0)
                    bail("setgroups failed");
            }

            if (config.cloneflags & CLONE_NEWCGROUP) {
                try_unshare(CLONE_NEWCGROUP, "cgroup namespace");
            }

            write_log(DEBUG, "signal completion to stage-0");
            s = SYNC_CHILD_FINISH;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s))
                bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");

            /* Close sync pipes. */
            if (close(sync_grandchild_pipe[0]) < 0)
                bail("failed to close sync_grandchild_pipe[0] fd");

            /* Free netlink data. */
            nl_free(&config);

            /* Finish executing, let the Go runtime take over. */
            write_log(DEBUG, "<= nsexec container setup");
            write_log(DEBUG, "booting up go runtime ...");
            return;
        } break;
        default:
            bail("unknown stage '%d' for jump value", current_stage);
    }

    /* Should never be reached. */
    bail("should never be reached");
}