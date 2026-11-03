/* pidfd_hunter - A simple tool to find hidden processes using pidfd_open
 * gcc -O2 -o pidfd_hunter pidfd_hunter.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <ctype.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#define MAX_PID 4194304 /* 4194304 for 64 bits, 32768 for 32 bits */

/**
 * Wrapper for the pidfd_open syscall. Returns a file descriptor on success, or -1 on failure.
 * @param pid The process ID to open a file descriptor for.
 * @param flags Flags for the pidfd_open syscall.
 * @return A file descriptor on success, or -1 on failure.
 */
static int pidfd_open_sys(pid_t pid, unsigned int flags)
{
    return syscall(SYS_pidfd_open, pid, flags);
}

/**
 * Checks if a string represents a valid number.
 * @param s The string to check.
 * @return 1 if the string is a valid number, 0 otherwise.
 */
static int is_number(const char *str)
{
    if (!str || !*str)
        return 0;

    for (const char *p = str; *p; p++)
    {
        if (!isdigit((unsigned char)*p))
            return 0;
    }

    return 1;
}

/**
 * Gets the maximum process ID allowed by the system.
 * @return The maximum process ID.
 */
static int get_pid_max(void)
{
    FILE *f = fopen("/proc/sys/kernel/pid_max", "r");
    if (!f)
        return MAX_PID;
    int value = 0;
    fscanf(f, "%d", &value);
    fclose(f);
    return value > 0 ? value : MAX_PID;
}

int main(void)
{
    int pid_max = get_pid_max();
    char *seen = calloc(pid_max + 1, 1);
    int found = 0;
    if (!seen)
        return 1;

    DIR *dir = opendir("/proc");
    if (!dir)
    {
        free(seen);
        return 1;
    }

    struct dirent *de;
    while ((de = readdir(dir)) != NULL)
    {
        if (!is_number(de->d_name))
            continue;
        long pid = strtol(de->d_name, NULL, 10);
        if (pid > 0 && pid <= pid_max)
            seen[pid] = 1;
    }
    closedir(dir);

    for (int pid = 1; pid <= pid_max; pid++)
    {
        if (seen[pid])
            continue;
        int fd = pidfd_open_sys(pid, 0);
        if (fd >= 0)
        {
            printf("[FOUND] PID %d exists but not in /proc\n", pid);
            found++;
            close(fd);
        }
    }

    free(seen);
    return found;
}