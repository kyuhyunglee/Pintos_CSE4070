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
  lock_init(&file_lock); // 전역 락 초기화
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* To-do: 각 sys call case당 해당 주소가 유효한지 검사하는 함수 구현 */
static void check_user_ptr(const void *ptr) {
  if (!is_user_vaddr(ptr) || ptr == NULL){
    //printf("invalid user pointer %p\n", ptr);
    exit(-1);
  }
  if (pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    //printf("invalid user pointer %p\n", ptr);
    exit(-1);
  }
  if (ptr >= PHYS_BASE) {
    //printf("invalid user pointer %p\n", ptr);
    exit(-1);
  }
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
  check_user_ptr(file); // 왠지 모르지만 이게 있어야 exec_bad_ptr 통과 아래 iteration의 경우에는 왜 안되는지 모르겠음
  if (file==NULL) return -1;
  // 문자열 전체가 유효한지 검사
  for(int i=0; i<strlen(file); i++){
    check_user_ptr(file + i);
  }
  return process_execute(file);
}

int wait(tid_t pid) {
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
  if (file==NULL) return -1;
  return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  if (file==NULL) return -1;
  return filesys_remove(file);
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
  check_user_ptr(f->esp);
  switch (*(uintptr_t *)f->esp) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_user_ptr(f->esp + 4);
      // esp + 4 는 다음으로 실행될 process의 주소이다
      exit(*(int *)(f->esp + 4));
      break;
    case SYS_EXEC:
      check_user_ptr(f->esp + 4);
      f->eax = exec((const char *)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_WAIT:
      check_user_ptr(f->esp + 4);
      f->eax = wait((tid_t)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_CREATE:
      check_user_ptr(f->esp + 4);
      check_user_ptr(f->esp + 8);
      f->eax = create((const char *)(*(uintptr_t *)(f->esp + 4)),
                      (unsigned int)(*(uintptr_t *)(f->esp + 8)));
      break;
    case SYS_REMOVE:
      check_user_ptr(f->esp + 4);
      f->eax = remove((const char *)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_OPEN:
      check_user_ptr(f->esp + 4);
      f->eax = open((const char *)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_FILESIZE:
      check_user_ptr(f->esp + 4);
      f->eax = filesize((int)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_READ:
      check_user_ptr(f->esp + 4);
      check_user_ptr(f->esp + 8);
      check_user_ptr(f->esp + 12);
      f->eax = read((int)(*(uintptr_t *)(f->esp + 4)),
                    (void *)(*(uintptr_t *)(f->esp + 8)),
                    (unsigned int)(*(uintptr_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      check_user_ptr(f->esp + 4);
      check_user_ptr(f->esp + 8);
      check_user_ptr(f->esp + 12);
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
  //printf ("system call! %d\n", *(uintptr_t *)f->esp);
  //thread_exit ();
}
