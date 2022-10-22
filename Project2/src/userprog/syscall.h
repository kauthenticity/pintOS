#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "process.h"

/* project1 system calls */
typedef int pid_t;

void syscall_init (void);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void*buffer, unsigned size);

/* project2 system calls */


bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* project1 additional system calls */
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

void verify_addr(int *addr);
void verify_NULL(void *pointer);
#endif /* userprog/syscall.h */
