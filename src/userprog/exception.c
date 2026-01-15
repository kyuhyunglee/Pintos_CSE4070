#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"  
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);


/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  struct thread *curr = thread_current();

  /* 1. 유효성 검사 (커널 주소, NULL 포인터) */
  if (is_kernel_vaddr(fault_addr) || fault_addr == NULL) {
      goto exit_process;
  }

  /* 2. SPT 확인 (lazy load / swap in) */
  struct vm_entry *vme = find_vme(fault_addr);

  if (vme != NULL) {
      if (write && !vme->writable) {
          goto exit_process;
      }

      /* [임시 조치] 파일 직접 읽기 */
      struct frame *frame = allocate_frame(PAL_USER); 
      if (frame == NULL) goto exit_process;

      void *kpage = frame->kpage;

      bool load_success = false;

      if (vme->swap_slot != 0) {
          /* Case 1: Swap Out 되었던 페이지 -> Swap In */
          // printf("[DEBUG] Swap In: Addr %p, Slot %d\n", vme->vaddr, vme->swap_slot);
          swap_in(vme->swap_slot, kpage);
          vme->swap_slot = 0; // 스왑 슬롯 비움
          load_success = true;
      }
      else if (vme->type == VM_FILE || (vme->type == VM_BIN && vme->file != NULL)) {
          /* Case 2: 파일에서 로딩 (Lazy Load) */
          if (vme->read_bytes > 0) {
              file_seek(vme->file, vme->offset);
              if (file_read(vme->file, kpage, vme->read_bytes) == (int)vme->read_bytes) {
                  memset(kpage + vme->read_bytes, 0, vme->zero_bytes);
                  load_success = true;
              }
          } else {
              memset(kpage, 0, PGSIZE);
              load_success = true;
          }
      } 
      else if (vme->type == VM_ANON) {
          /* Case 3: 처음 접근하는 스택/힙 페이지 -> 0으로 초기화 */
          memset(kpage, 0, PGSIZE);
          load_success = true;
      }

      if (!load_success) {
          free_frame(frame);
          goto exit_process;
      }

      // 페이지 테이블 매핑도 실제 메모리 주소(kpage)로 해야 합니다.
      if (!pagedir_set_page(curr->pagedir, vme->vaddr, kpage, vme->writable)) {
          free_frame(frame);
          goto exit_process;
      }

      vme->is_loaded = true;
      frame->vme = vme;
      return;
  }

  /* 3. Stack Growth (스택 확장) */
  // thread 구조체에 rsp가 추가되고 컴파일됨
  void *esp = user ? f->esp : curr->rsp;
  
  // 스택 유효 범위: PHYS_BASE 아래 8MB && esp 근처(32바이트)
  if (fault_addr >= (void *)((uint8_t *) PHYS_BASE - (1 << 23)) && 
      fault_addr <= (void *) PHYS_BASE &&
      fault_addr >= (esp - 32)) 
  {
      void *upage = pg_round_down(fault_addr);
      
      /* 이미 페이지가 할당되어 있는지 이중 체크 (필요시) */
      if (find_vme(upage) != NULL) goto exit_process;

      struct vm_entry *new_vme = malloc(sizeof(struct vm_entry)); // malloc 헤더 필요
      if (new_vme == NULL) goto exit_process;

      memset(new_vme, 0, sizeof(struct vm_entry));
      new_vme->type = VM_ANON;
      new_vme->vaddr = upage;
      new_vme->writable = true;
      new_vme->is_loaded = true;
      new_vme->pinned = true;

      if (!insert_vme(&curr->vm, new_vme)) {
          free(new_vme);
          goto exit_process;
      }

      struct frame *frame_ptr = allocate_frame(PAL_USER | PAL_ZERO);
      if (frame_ptr == NULL) {
          delete_vme(&curr->vm, new_vme);
          goto exit_process;
      }
      
      void *kpage = frame_ptr->kpage;

      if (!pagedir_set_page(curr->pagedir, upage, kpage, true)) {
          free_frame(frame_ptr);
          delete_vme(&curr->vm, new_vme);
          goto exit_process;
      }
      
      return;
  }

exit_process:
  if (user || is_user_vaddr(fault_addr)) {
      printf ("%s: exit(-1)\n", thread_current ()->name);
      thread_current ()->exit_status = -1;
      thread_exit ();
  }

  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}