#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include <string.h>             // <--- strlen 사용을 위해 추가
#include "devices/shutdown.h"   // <--- shutdown_power_off 사용을 위해 추가
#include "filesys/filesys.h"    // <--- filesys_create, remove, open 사용을 위해 추가
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
struct lock file_lock;

void
syscall_init (void) 
{
  lock_init(&file_lock); // 전역 락 초기화
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* To-do: 각 sys call case당 해당 주소가 유효한지 검사하는 함수 구현 */
// ptr 부터 ptr+3 까지 블럭 단위로 검사
static void check_user_ptr(const void *ptr) {
  if (ptr == NULL || !is_user_vaddr(ptr) || !is_user_vaddr(ptr + 3)) {
        exit(-1);
    }
  for (int i = 0; i < 4; i++) {
        if (pagedir_get_page(thread_current()->pagedir, ptr + i) == NULL) {
            exit(-1);
        }
    }
}

/* 버퍼가 유효한지 검사 (write 시스템 콜 등에서 사용) */
static void check_user_buffer(const void *buffer, unsigned size) {
    const uint8_t *ptr = (const uint8_t *)buffer;
    struct thread *cur = thread_current();

    for (unsigned i = 0; i < size; i++) {
        const void *addr = ptr + i;

        // 1. 사용자 영역 주소인지 확인
        if (!is_user_vaddr(addr)) {
            exit(-1);
        }

        // 2. SPT에 존재하는지 확인 (Lazy Loading 페이지도 유효한 것으로 간주)
        struct vm_entry *vme = find_vme((void *)addr);
        
        // 3. SPT에 없다면, 스택 확장 가능 영역인지 추가 확인 가능하나
        //    일반적으로 힙/스택에 할당되지 않은 주소는 접근 불가여야 함
        if (vme == NULL) {
             exit(-1);
        }
    }
}

/* 버퍼가 유효한 사용자 주소이며, '쓰기 가능(Writable)'한지 검사 */
static void check_writable_buffer(void *buffer, unsigned size) {
    struct vm_entry *vme;
    uint8_t *ptr = (uint8_t *)buffer;

    for (unsigned i = 0; i < size; i++) {
        void *addr = ptr + i;
        
        // 1. 사용자 영역 주소인지 확인
        if (!is_user_vaddr(addr)) {
            exit(-1);
        }

        // 2. SPT에서 vme 검색
        vme = find_vme(addr);
        if (vme != NULL) {
            // 3. 쓰기 권한이 있는지 확인 (Code Segment는 writable이 false임)
            if (!vme->writable) {
                exit(-1);
            }
        }
        // vme가 NULL인 경우(Stack Growth 등)는 page_fault 핸들러가 처리하도록 둠
        // 다만 read 시스템 콜의 특성상 미리 할당되지 않은 영역에 쓰려고 하면 
        // 일반적으로는 여기서 잡아주는 것이 안전함.
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
  if (file==NULL) exit(-1);
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
  check_user_ptr(file);
  if (file==NULL) exit(-1);

  lock_acquire(&file_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);

  return success;
}

bool remove(const char *file) {
  if (file==NULL) exit(-1);

  lock_acquire(&file_lock);
  bool success = filesys_remove(file);
  lock_release(&file_lock);

  return success;
}

int open(const char *file) {
  check_user_ptr(file);
  if (file==NULL) exit(-1);
  
  lock_acquire(&file_lock); // 락 획득
  struct file *f = filesys_open(file);
  
  if (f == NULL) {
    lock_release(&file_lock); // 실패 시 락 해제
    return -1; 
  }
  
  struct thread *cur = thread_current();
  int fd;
  for (fd = 3; fd < 128; fd++) {
    if (cur->file_descriptor[fd] == NULL) {
      cur->file_descriptor[fd] = f;
      lock_release(&file_lock); // 성공 시 락 해제
      return fd;
    }
  }
  
  file_close(f);
  lock_release(&file_lock); // fd 부족 시 락 해제
  return -1;
}

int filesize(int fd) {
  if (fd < 3 || fd >= 128) return -1;
  struct thread *cur = thread_current();
  
  lock_acquire(&file_lock); // 락 획득
  struct file *f = cur->file_descriptor[fd];
  if (f == NULL) {
      lock_release(&file_lock);
      return -1;
  }
  int length = file_length(f);
  lock_release(&file_lock); // 락 해제
  
  return length;
}

int read(int fd, void *buffer, unsigned int size) {
  check_writable_buffer(buffer, size);
  if (fd < 0 || fd >= 128 || fd == 1) return -1;
  lock_acquire(&file_lock); // 파일 시스템 접근 시 락 획득
  if (fd == 0) {
    unsigned i;
    printf("read process\n");
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
    }
    printf("read %d bytes\n", size);
    lock_release(&file_lock); // 락 해제
    return size;
  }
  // fd가 0이 아닌 경우 implementation 필요
  else{
    struct thread *cur = thread_current();
    struct file *f = cur->file_descriptor[fd];
    if (f == NULL) {
      lock_release(&file_lock); // 락 해제
      return -1; // 해당 fd가 열려있지 않음
    }
    int bytes_read = file_read(f, buffer, size);
    lock_release(&file_lock); // 락 해제
    return bytes_read;
  }
}

int write(int fd, const void *buffer, unsigned int size) {
  check_user_buffer(buffer, size);
  if (fd < 0 || fd >= 128 || fd == 0) return -1;
  lock_acquire(&file_lock); // 파일 시스템 접근 시 락 획득
  if (fd == 1) {
    //printf("[DEBUG] syscall_write: fd=%d, size=%u\n", fd, size);
    putbuf(buffer, size);
    lock_release(&file_lock); // 락 해제
    return size;
  }
  // fd가 1이 아닌 경우 implementation 필요
  else {
    struct thread *cur = thread_current();
    struct file *f = cur->file_descriptor[fd];
    if (f == NULL) {
      lock_release(&file_lock); // 락 해제
      return -1; // 해당 fd가 열려있지 않음
    }
    int bytes_written = file_write(f, buffer, size);
    lock_release(&file_lock); // 락 해제
    return bytes_written;
  }
}

void seek(int fd, unsigned position) {
  if (fd < 3 || fd >= 128) return;
  struct thread *cur = thread_current();
  
  lock_acquire(&file_lock); // 락 획득
  struct file *f = cur->file_descriptor[fd];
  if (f == NULL){
    lock_release(&file_lock);
    return;
  }
  file_seek(f, position);
  lock_release(&file_lock); // 락 해제
}

unsigned tell(int fd) {
  if (fd < 3 || fd >= 128) return -1;
  struct thread *cur = thread_current();
  
  lock_acquire(&file_lock); // 락 획득
  struct file *f = cur->file_descriptor[fd];
  if (f == NULL){
    lock_release(&file_lock);
    return -1;
  }
  unsigned pos = file_tell(f);
  lock_release(&file_lock); // 락 해제
  return pos;
}

int close(int fd) {
  if (fd < 3 || fd >= 128) return -1;
  struct thread *cur = thread_current();
  
  lock_acquire(&file_lock); // 락 획득
  struct file *f = cur->file_descriptor[fd];
  if (f == NULL){
    lock_release(&file_lock);
    return -1; 
  }
  file_close(f);
  cur->file_descriptor[fd] = NULL;
  lock_release(&file_lock); // 락 해제
  return 0;
}

mapid_t mmap(int fd, void *addr) {
  // mmap 내부에서 file_reopen 등을 수행하므로 락 필요
  lock_acquire(&file_lock);
  mapid_t ret = mm_mapping(fd, addr);
  lock_release(&file_lock);
  return ret;
}

void munmap(mapid_t mapid) {
  // munmap 내부에서 file_write, file_close 등을 수행하므로 락 필요
  lock_acquire(&file_lock);
  mm_freeing(mapid);
  lock_release(&file_lock);
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
  thread_current()->rsp = f->esp;
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
      check_user_ptr(f->esp + 4);
      check_user_ptr(f->esp + 8);
      seek((int)(*(uintptr_t *)(f->esp + 4)),
           (unsigned int)(*(uintptr_t *)(f->esp + 8)));
      break;
    case SYS_TELL:
      check_user_ptr(f->esp + 4);
      f->eax = tell((int)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_CLOSE:
      check_user_ptr(f->esp + 4);
      f->eax = close((int)(*(uintptr_t *)(f->esp + 4)));
      break;
    case SYS_MMAP:
      check_user_ptr(f->esp + 4);
      check_user_ptr(f->esp + 8);
      f->eax = mmap((int)(*(uintptr_t *)(f->esp + 4)),
                    (void *)(*(uintptr_t *)(f->esp + 8)));
      break;
    case SYS_MUNMAP:
      check_user_ptr(f->esp + 4); // mapid
      munmap((mapid_t)(*(uintptr_t *)(f->esp + 4)));
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
