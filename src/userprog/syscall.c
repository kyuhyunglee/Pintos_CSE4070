#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "lib/kernel/console.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  cur->exit_status = status;
  thread_exit();
}

tid_t exec(const char *file) {
  return process_execute(file);
}

int wait(tid_t pid) {
  return process_wait(pid);
}

int read(int fd, void *buffer, unsigned int size) {
  if (fd == 0) {
    unsigned i;
    printf("read process\n");
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    printf("read %d bytes\n", size);
    return size;
  }
  else return -1;
}

int write(int fd, const void *buffer, unsigned int size) {
  if (fd == 1) {
    //printf("[DEBUG] syscall_write: fd=%d, size=%u\n", fd, size);
    putbuf(buffer, size);
    return size;
  }
  else return -1;
}

int fibonacci(int n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

int max_of_four_int(int a, int b, int c, int d) {
  int max = a;
  if (b > max) max = b;
  if (c > max) max = c;
  if (d > max) max = d;
  return max;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  ASSERT (intr_get_level () == INTR_ON);
  switch (*(uintptr_t *)f->esp) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      // esp + 4 는 다음으로 실행될 process의 주소이다
      exit(*(int *)(f->esp + 4));
      break;
    case SYS_EXEC:
      f->eax = exec((const char *)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_WAIT:
      f->eax = wait((tid_t)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_CREATE:
      break;
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      f->eax = read((int)(*(uintptr_t *)(f->esp + 4)),
                    (void *)(*(uintptr_t *)(f->esp + 8)),
                    (unsigned int)(*(uintptr_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      f->eax = write((int)(*(uintptr_t *)(f->esp + 4)),
                     (const void *)(*(uintptr_t *)(f->esp + 8)),
                     (unsigned int)(*(uintptr_t *)(f->esp + 12)));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    case SYS_FIBONACCI:
      f->eax = fibonacci((int)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_MAX_OF_FOUR_INT:
      f->eax = max_of_four_int((int)(*(uintptr_t *)(f->esp + 4)),
                               (int)(*(uintptr_t *)(f->esp + 8)),
                               (int)(*(uintptr_t *)(f->esp + 12)),
                               (int)(*(uintptr_t *)(f->esp + 16)));
      break;
  }
  // 추후 process_wait 구현, process_exit 구현 시에 주석 해제
  // 지금은 system call이 호출되면 바로 종료
  //printf ("system call! %d\n", *(uintptr_t *)f->esp);
  //thread_exit ();
  //shutdown_power_off ();
}
