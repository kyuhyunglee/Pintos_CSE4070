#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

void syscall_init (void);
void halt(void);
void exit(int status);
tid_t exec(const char *file);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned int size);
int write(int fd, const void *buffer, unsigned int size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* 새로운 syscall handling용 함수 */
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

#endif /* userprog/syscall.h */
