#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h" // file_reopen 등을 위해 필요
#include "filesys/file.h"

/* 외부 Lock (syscall.c 등에서 정의된 파일 시스템 접근 락) */
// extern struct lock filesys_lock; // 필요하다면 주석 해제하여 사용

static struct file *mm_get_file (int fd);
static struct mm_entry *mm_get_entry (mapid_t mapid);

mapid_t
mm_mapping (int fd, void *addr)
{
  struct thread *cur = thread_current();
  struct mm_entry *mme; 
  struct vm_entry *vme; // pt_entry -> vm_entry 변경
  size_t ofs = 0; 
  off_t file_len;
  off_t remaining;

  /* Validation checks */
  if (IS_INVALID_VA(addr)) return MMAP_ERROR;
  if (IS_MISALIGNED(addr)) return MMAP_ERROR;
  // pt_find_entry -> find_vme 변경
  if (find_vme(addr)) return MMAP_ERROR;

  mme = (struct mm_entry *)malloc(sizeof(struct mm_entry));
  if (mme == NULL)
    return MMAP_ERROR;
  
  /* Initialize entry */
  // mm_list_size가 thread 구조체에 없다면 직접 관리하거나 mapid 생성 로직 필요
  // 여기서는 단순히 정적 변수나 리스트 크기로 처리하지 않고, 
  // 보통 mapid는 fd처럼 유니크하면 되므로 cur->mapid_cnt 등을 thread.h에 추가하는 것 추천
  mme->mapid = cur->next_mapid++; // thread 구조체에 next_mapid 추가 필요 (초기값 1)
  
  list_init (&mme->pte_list);
  
  /* File Access */
  // lock_acquire (&filesys_lock); // 파일 시스템 락 필요시 사용
  struct file *raw_file = mm_get_file(fd);
  if (raw_file) {
      mme->file = file_reopen(raw_file);
  } else {
      mme->file = NULL;
  }
  // lock_release (&filesys_lock);

  if (mme->file == NULL) {
      free(mme);
      return MMAP_ERROR;
  }

  list_push_back (&(cur->mmap_list), &(mme->elem)); // mm_list -> mmap_list

  /* Map pages */
  file_len = file_length (mme->file);
  remaining = file_len;

  while (remaining > 0)
    {
      size_t page_read_bytes;
      size_t page_zero_bytes;

      if (remaining < PGSIZE) {
          page_read_bytes = remaining;
      } else {
          page_read_bytes = PGSIZE;
      }
      page_zero_bytes = PGSIZE - page_read_bytes;

      /* vm_entry 생성 및 설정 */
      vme = malloc(sizeof(struct vm_entry));
      if (vme == NULL) {
          // 이미 할당된 것들 해제하는 롤백 로직이 필요하지만, 여기선 생략
          return MMAP_ERROR;
      }

      vme->type = VM_FILE; // mmap은 파일 타입
      vme->vaddr = addr;
      vme->writable = true;
      vme->is_loaded = false; // Lazy Loading
      vme->file = mme->file;
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      
      /* SPT에 추가 */
      if (!insert_vme(&cur->vm, vme)) {
          free(vme);
          return MMAP_ERROR;
      }
      
      /* mmap 관리 리스트에 추가 */
      list_push_back (&(mme->pte_list), &(vme->mm_elem));

      addr = (char *)addr + PGSIZE;
      ofs += PGSIZE;
      remaining -= PGSIZE;
    }

  return mme->mapid;
}

void 
mm_freeing (mapid_t mapid)
{
  struct mm_entry *mme;
  struct thread *cur = thread_current();
  
  mme = mm_get_entry (mapid);
  if (mme == NULL) return;
  
  while (!list_empty(&mme->pte_list))
  {
      struct list_elem *e = list_pop_front(&mme->pte_list);
      struct vm_entry *vme = list_entry(e, struct vm_entry, mm_elem);

      if (vme->is_loaded) {
          if (pagedir_is_dirty(cur->pagedir, vme->vaddr)) {
              // lock_acquire (&filesys_lock);
              file_write_at (vme->file, vme->vaddr, vme->read_bytes, vme->offset);
              // lock_release (&filesys_lock);
          }
          
          // 물리 프레임 해제 (allocate_frame에 대응)
          free_frame_by_vaddr(vme->vaddr); // frame.c에 해당 함수 구현 필요 또는 palloc_free_page 사용
          pagedir_clear_page(cur->pagedir, vme->vaddr);
      }

      /* SPT에서 제거 */
      delete_vme(&cur->vm, vme);
  }

  // 파일 닫기
  file_close(mme->file);

  list_remove (&(mme->elem));
  free (mme);
}

static struct file *
mm_get_file (int fd)
{
  struct thread *cur = thread_current();
  // fd 배열 검증
  if (fd < 2 || fd >= 128) return NULL; // FD_MAX 상수가 없다면 128 등 사용
  return cur->file_descriptor[fd]; // cur->fd 인지 cur->file_descriptor 인지 확인
}

static struct mm_entry *
mm_get_entry (mapid_t mapid)
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list); e = list_next (e))
    {
      struct mm_entry *mme = list_entry (e, struct mm_entry, elem);
      if (mme->mapid == mapid)
        return mme;
    }
  return NULL;
}