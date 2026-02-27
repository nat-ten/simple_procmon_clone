#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/reg.h>

#define MAX_SIZE 1024

struct params* createArgs(pid_t current_processes[], pid_t pid);
void initList(pid_t current_processes[]);
void delete(pid_t current_processes[], pid_t pid);
void insert(pid_t current_processes[], pid_t pid);
bool inList(pid_t current_processes[], pid_t pid);
bool isPID(char* filename);
int tracePID(pid_t pid);
void* trace(void* arg);
char* getExecName(pid_t pid);

struct params {
    pid_t pid;
    pid_t* current_processes;
};

const char* syscalls[] = 
{
"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
"ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl",
"dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
"shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname",
"semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
"chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask",
"gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp",
"setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
"rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam",
"sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex",
"setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module",
"delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
"lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy",
"io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime",
"timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch",
"migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
"unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime",
"accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at",
"open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create",
"kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx", "io_pgetevents", "rseq", "uretprobe",
"pidfd_send_signal", "io_uring_setup", "io_uring_enter", "io_uring_register", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "pidfd_open", "clone3", "close_range", "openat2", "pidfd_getfd", "faccessat2",
"process_madvise", "epoll_pwait2", "mount_setattr", "quotactl_fd", "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "memfd_secret", "process_mrelease", "futex_waitv", "set_mempolicy_home_node", "cachestat", "fchmodat2", "map_shadow_stack", "futex_wake", "futex_wait",
"futex_requeue", "statmount", "listmount", "lsm_get_self_attr", "lsm_set_self_attr", "lsm_list_modules", "mseal", "setxattrat", "getxattrat", "listxattrat", "removexattrat", "open_tree_attr"
};

int main() {
    pid_t current_processes[MAX_SIZE];
    initList(current_processes);
    insert(current_processes, getpid());

    while (1) {
        DIR* proc = opendir("/proc");
        if (proc == NULL) {
            perror("Failed to open /proc\n");
            exit(EXIT_FAILURE);
        }
        struct dirent* dir;

        while ((dir = readdir(proc)) != NULL) {
            bool process, is_traced;
            process = isPID(dir->d_name);
            pid_t pid;

            if (process) {
                pid = atoi(dir->d_name);
                is_traced = inList(current_processes, pid);
            }

            if (process && !is_traced) {
                struct params* args = createArgs(current_processes, pid);
                void* ret;
                pthread_t thread;

                insert(current_processes, pid);
                pthread_create(&thread, NULL, trace, args);
            }
        }

        closedir(proc);
    }
    exit(EXIT_SUCCESS);
}

struct params* createArgs(pid_t current_processes[], pid_t pid) {
    struct params* new_params = malloc(sizeof(struct params));
    if (new_params == NULL) {
        perror("Unable to allocate memory for new params\n");
        return NULL;
    }

    new_params->current_processes = &current_processes[0];
    new_params->pid = pid;

    return new_params;
}

void initList(pid_t current_processes[]) {
    for (int i = 0; i < MAX_SIZE; i++) {
        current_processes[i] = -1;
    }
}

void* trace(void* arg) {
    struct params* args = (struct params*)arg;
    pid_t pid = args->pid;
    int result = tracePID(pid);
    if (result == 0) {
        delete(args->current_processes, pid);
    }

    pthread_exit(NULL);
}

int tracePID(pid_t pid) {
    int status;
    long call, ret;
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        return -1;
    }

    char* name = getExecName(pid);
    struct user_regs_struct regs;
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (status != 1407) {
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        call = regs.orig_rax;
        if (call > 424) {
            call -= 88;
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        if (status != 1407) {
            break;
        }

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        ret = regs.rax;
        printf("Process %d: %s invoked \"%s\" with a return value of %ld\n", pid, name, syscalls[call], ret);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

char* getExecName(pid_t pid) {
    char* file_name = malloc(sizeof("/proc") + sizeof(pid_t) + sizeof("/cmdline"));
    if (sprintf(file_name, "/proc/%d/cmdline", pid) < 0) {
        perror("sprintf failed\n");
        return NULL;
    }
    
    FILE* file = fopen(file_name, "r");
    if (file == NULL) {
        perror("Unable to open file\n");
        return NULL;
    }

    char* buffer = malloc(sizeof(char) * 1024);

    if (file) {
        int size;
        size = fread(buffer, sizeof(char), 1024, file);

        if(size > 0) {
            if ('\n' == buffer[size - 1]) {
                buffer[size - 1] = '\0';
            }
        }
    }

    fclose(file);

    return buffer;
}

bool isPID(char* filename) {
    bool valid = true;

    for (int i = 0; filename[i] != '\0'; i++) {
        if (filename[i] <= '0' || filename[i] >= '9') {
            valid = false;
            break;
        }
    }

    return valid;
}

bool inList(pid_t current_processes[], pid_t pid) {
    int i = 0;
    bool result = false;
    while (i < MAX_SIZE) {
        if (current_processes[i] == pid) {
            result = true;
            break;
        }
        i++;
    }

    return result;
}

void insert(pid_t current_processes[], pid_t pid) {
    int i = 0;
    bool insert = false;
    while (i < MAX_SIZE) {
        if (current_processes[i] == -1) {
            current_processes[i] = pid;
            insert = true;
            break;
        }
        i++;
    }
}

void delete(pid_t current_processes[], pid_t pid) {
    int i = 0;
    bool delete = false;
    while (i < MAX_SIZE) {
        if (current_processes[i] == pid) {
            current_processes[i] = -1;
            delete = true;
        }
        i++;
    }
}
