#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "vm/page.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parse the file name to get the executable name only */
  char file_name_copy[64];
  char *save_ptr;
  strlcpy(file_name_copy, file_name, sizeof(file_name_copy));
  char *exec_name = strtok_r(file_name_copy, " ", &save_ptr);

  struct child_entry *entry = malloc(sizeof(struct child_entry));
  if (entry == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  entry->tid = TID_ERROR; // 나중에 설정
  entry->exit_status = 0; // 초기화 확인
  entry->load_success = false;
  sema_init(&entry->load_sema, 0);
  sema_init(&entry->exit_sema, 0);

  struct execute_args *args = malloc(sizeof(struct execute_args));
  if (args == NULL) {
    free(entry);
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  args->file_name = fn_copy;
  args->entry = entry;

  tid = thread_create (exec_name, PRI_DEFAULT, start_process, args);
    
  if (tid == TID_ERROR) {
    free(entry);
    free(args);
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }

  entry->tid = tid;
  list_push_back(&thread_current()->children, &entry->elem);

  sema_down(&entry->load_sema);
    
  if (entry->load_success == false) {
    // 로드 실패 시 entry는 process_wait에서 해제할 수 있도록 두거나,
    // 여기서 리스트에서 제거하고 해제해야 합니다.
    // 핀토스 테스트 케이스상 보통 wait(-1)을 호출하므로 일단 둡니다.
    // 또는 여기서 정리:
    list_remove(&entry->elem);
    free(entry);
    return -1;
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct execute_args *args = (struct execute_args *)args_;
  char *file_name = args->file_name;
  struct child_entry *entry = args->entry;

  struct thread *t = thread_current();
  t->pcb = entry;

  free(args);

  struct intr_frame if_;
  bool success;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  t->pcb->load_success = success;
  sema_up(&t->pcb->load_sema);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success){
    thread_exit ();
  }

  /* 만약 세마포가 올라와 있다면 file을 close해준다 
  if (thread_current()->load_sema.value > 0 && thread_current()->exec_file != NULL){
    file_close(thread_current()->exec_file); // exec file close
    thread_current()->exec_file = NULL;
  }
  */

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct child_entry *child_entry = NULL;

  /*  자식 리스트에서 tid에 해당하는 entry 찾기 */
  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
    struct child_entry *entry = list_entry(e, struct child_entry, elem);
    if (entry->tid == child_tid) {
      child_entry = entry;
      break;
    }
  }

  if (child_entry == NULL) return -1; // 해당 자식이 없음

  /* 종료 대기 */
  sema_down(&child_entry->exit_sema);
    
  int exit_status = child_entry->exit_status;
    
  /* 리스트에서 제거 및 entry 메모리 해제 */
  list_remove(&child_entry->elem);
  free(child_entry); 
    
  /* 주의: palloc_free_page(child_thread)는 절대 하지 않음! 
       스레드 스택은 스레드가 완전히 죽은 뒤 스케줄러가 해제함. */

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  process_cleanup();

  if (cur->vm.buckets) vm_destroy(&cur->vm);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (cur->pcb != NULL) {
    cur->pcb->exit_status = cur->exit_status; // thread_exit 등에서 미리 설정되었다고 가정
    sema_up(&cur->pcb->exit_sema);
  }
  //printf("sema up in exit\n");

  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  vm_init(&t->vm); // Supplemental Page Table 초기화

  // 이전에 파싱 필요
  char file_name_copy[64];
  char *save_ptr;
  strlcpy(file_name_copy, file_name, sizeof(file_name_copy));
  char *exec_name = strtok_r(file_name_copy, " ", &save_ptr);
  strlcpy(t->name, exec_name, sizeof(t->name));

  /* Open executable file. */
  file = filesys_open (exec_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", exec_name);
      goto done; 
    }
  /* 동시에 해당 파일에 쓰지 못하게 막는다 */
  t->exec_file = file;
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    // 비정상적인 스택 형성 시에 done으로 이동
    goto done;

  //printf("DEBUG: setup_stack success. Starting argument passing.\n");
  // 위에서 정상적으로 stack 이 설정되고, 이제 stack_frame 작성
  char *argv[64];
  int argc = 0;
  char *token = exec_name;

  // argv에 argument 저장
  // argc에는 argument 개수 저장
  strlcpy(file_name_copy, file_name, sizeof(file_name_copy));
  for(token = strtok_r(file_name_copy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
    if (argc < 63) {
      argv[argc++] = token;
      //printf("token %s\n", token);
    }
  }
  //printf("argc : %d\n", argc);

  // argv 값을 역순으로 stack에 저장
  char *argv_user_adder[64];
  for (i = argc - 1; i >= 0; i--) {
    int token_len = strlen(argv[i]) + 1; // \t때문에 +1
    *esp -= token_len;
    memcpy(*esp, argv[i], token_len);
    argv_user_adder[i] = *esp; // argument의 user virtual address 저장
    //printf("file name token %s\n", *esp);
  }

  // 32bit word align
  while ((uintptr_t)*esp % 4 != 0) {
    *esp -= 1;
    *(uint8_t *)(*esp) = 0; 
  }

  // argv_user_adder를 stack에 저장
  *esp -= sizeof(char *);
  *(char **)(*esp) = NULL;
  for (i = argc - 1; i >= 0; i--) {
    *esp -= sizeof(char *);
    *(char **)(*esp) = argv_user_adder[i]; // argv[i]의 주소 저장
  }

  char **argv_ptr = *esp;
  *esp -= sizeof(char **);
  *(char ***)(*esp) = argv_ptr; // argv의 주소 저장
  *esp -= sizeof(int);
  *(int *)(*esp) = argc; // argc 저장
  *esp -= sizeof(void *);
  *(void **)(*esp) = NULL; // return address 0

  //디버깅용 hex_dump
  //printf("DEBUG: Argument passing done. Hex dump:\n");
  //hex_dump(*esp, *esp, 100, true);
  
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // 실행 중인 파일에는 쓰기 금지
  //printf("DEBUG: load function finished. success = %d\n", success);

  if (thread_current()->pcb != NULL) {
      sema_up(&thread_current()->pcb->load_sema);
  }
  //printf("sema up in load\n");
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
// VM 구현하면서 Lazy Load로 변경 vm_entry을 SPT에 추가만 한다
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  //file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. 
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;
      */

      struct vm_entry *vme = malloc(sizeof(struct vm_entry));
      if (vme == NULL)
        return false;

      vme->type = VM_BIN; // 우선 바이너리로 설정, 나중에 파일 매핑 등으로 확장 가능
      vme->vaddr = upage;
      vme->writable = writable;
      vme->is_loaded = false;

      vme->file = file;
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->swap_slot = 0;

      /* Load this page. 
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

       Add the page to the process's address space. 
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
      */

      // SPT에 vm_entry 추가
      struct thread *t = thread_current();
      if (!insert_vme(&t->vm, vme)) {
        free(vme);
        return false;
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct frame *kpage;
  bool success = false;

  //kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  kpage = allocate_frame(PAL_USER | PAL_ZERO);
  if (kpage == NULL) {
    printf("DEBUG: setup_stack failed at allocate_frame\n"); // 디버깅
    return false;
  }

  if (kpage != NULL) 
    {
      uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;

      struct vm_entry *vme = malloc(sizeof(struct vm_entry));
      if (vme == NULL) {
        free_frame(kpage);
        return false;
      }

      vme->type = VM_ANON; // 스택은 익명 페이지
      vme->vaddr = upage;
      vme->writable = true;
      vme->is_loaded = true; // 스택은 즉시 로드됨
      vme->swap_slot = 0; // 스왑 슬롯은 아직 없음
      vme->pinned = true;

      kpage->vme = vme; // 프레임과 vm_entry 연결

      if (!insert_vme(&thread_current()->vm, vme)) {
        printf("DEBUG: setup_stack failed at insert_vme\n");
        free(vme);
        free_frame(kpage);
        return false;
      }

      // 주의: install_page 내부에서 palloc을 다시 하지 않도록 수정하거나,
      // pagedir_set_page를 직접 호출해야 함. 
      // 기존 install_page는 palloc을 안 쓰지만 pagedir_set_page만 하므로 재사용 가능.
      // install_page의 인자로 kpage->kpage (커널 주소)를 넘김.
      
      success = install_page (upage, kpage->kpage, true);

      //success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        vme->pinned = true;
        *esp = PHYS_BASE;
      }
      else {
        printf("DEBUG: setup_stack failed at install_page\n");
        delete_vme(&thread_current()->vm, vme);
        // delete_vme는 free(vme)를 하겠지만 frame 해제는 별도로 챙겨야 할 수도 있음
        // 여기서는 간단히 실패 처리
        free_frame(kpage);
      }
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

struct thread* get_child_process_by_tid(tid_t child_tid) {
  intr_disable();
  struct thread* cur = thread_current();
  struct list_elem* e;

  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
    struct thread* child = list_entry(e, struct thread, child_elem);
    if (child->tid == child_tid) {
      intr_enable();
      return child;
    }
  }
  intr_enable();
  return NULL;
}

void process_cleanup(void) {
  /* 현재 프로세스의 fd를 정리 */
  struct thread *cur = thread_current();
  for (int fd = 3; fd < 128; fd++) {
    if (cur->file_descriptor[fd] != NULL) {
      file_close(cur->file_descriptor[fd]);
      cur->file_descriptor[fd] = NULL;
    }
  }
  /* 실행 중이던 실행 파일의 쓰기 금지를 해제하고 닫는다. */
    if (cur->exec_file != NULL) {
        file_close(cur->exec_file);
        cur->exec_file = NULL;
    }

    /* 자식 리스트에 남아있는 정보들을 정리한다. */
    while (!list_empty(&cur->children)) {
        struct list_elem *e = list_pop_front(&cur->children);
        struct child_entry *entry = list_entry(e, struct child_entry, elem);
        free(entry); // 자식 프로세스 정보 구조체 해제
    }
}