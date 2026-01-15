/* vm/frame.c */
#include "vm/frame.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include <list.h>

// 전역 프레임 테이블 (모든 활성 프레임을 관리)
static struct list frame_table;
// 프레임 테이블 접근을 보호하기 위한 락
static struct lock frame_table_lock;
// Clock 알고리즘용 포인터
static struct list_elem *clock_hand;

/* 프레임 테이블 초기화 */
void
vm_frame_init (void)
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);
    clock_hand = NULL;
}

/* 내부 함수: 희생자(Victim) 페이지 선정 및 메모리 확보 */
static void *
vm_evict_frame (void)
{
    struct frame *victim = NULL;
    struct thread *t = thread_current();

    lock_acquire (&frame_table_lock);

    /* Clock Algorithm: accessed bit가 0인 프레임을 찾을 때까지 순회 */
    if (list_empty(&frame_table)) {
        lock_release(&frame_table_lock);
        PANIC("Frame table is empty, cannot evict!");
    }

    if (clock_hand == NULL || list_end(&frame_table) == clock_hand) {
        clock_hand = list_begin (&frame_table);
    }

    while (true) {
        struct frame *f = list_entry (clock_hand, struct frame, elem);
        
        /* 다음 검사할 프레임으로 이동 (Circular) */
        clock_hand = list_next (clock_hand);
        if (clock_hand == list_end (&frame_table)) {
            clock_hand = list_begin (&frame_table);
        }

        /* 1. 고정된 페이지(Pinned)는 건너뜀 (Stack Setup 중이거나 DMA 중 등) */
        if (f->vme->pinned) {
            continue;
        }

        /* 2. Accessed Bit 확인 (Second Chance) */
        if (pagedir_is_accessed (f->t->pagedir, f->vme->vaddr)) {
            pagedir_set_accessed (f->t->pagedir, f->vme->vaddr, false);
            continue;
        }

        /* 희생자 당첨 */
        victim = f;
        break;
    }

    /* Victim 처리: Swap Out 또는 File Write */
    struct vm_entry *vme = victim->vme;
    
    // 이미 victim이 다른 스레드의 소유일 수 있음
    bool is_dirty = pagedir_is_dirty(victim->t->pagedir, vme->vaddr);

    // 파일 시스템 접근 전 락 확인
    bool lock_held = lock_held_by_current_thread(&file_lock);

    switch (vme->type) {
        case VM_BIN:
            /* 실행 파일 코드 영역은 읽기 전용이므로 그냥 버림 (다시 읽으면 됨) 
               단, dirty라면 swap으로 보내야 할 수도 있지만 보통 코드는 dirty가 안됨 */
             if (is_dirty) { 
                 vme->swap_slot = swap_out(victim->kpage);
                 vme->type = VM_ANON; // 내용이 변했으므로 익명 페이지 취급
             }
            break;

        case VM_FILE:
            /* mmap된 파일: 변경되었다면 파일에 기록 */
            if (is_dirty) {
                if (!lock_held) lock_acquire(&file_lock);
                file_write_at(vme->file, victim->kpage, vme->read_bytes, vme->offset);
                if (!lock_held) lock_release(&file_lock);
            }
            break;

        case VM_ANON:
        default:
            /* 스택, 힙 등: 스왑 영역으로 이동 */
            vme->swap_slot = swap_out(victim->kpage);
            break;
    }

    /* 메모리 해제 절차 */
    vme->is_loaded = false;
    pagedir_clear_page(victim->t->pagedir, vme->vaddr);
    
    void *kpage = victim->kpage;
    
    // 리스트에서 제거
    list_remove (&victim->elem);
    
    // 구조체 해제
    free(victim);
    
    // 물리 메모리 해제
    palloc_free_page(kpage);

    lock_release (&frame_table_lock);

    return NULL; // 리턴값은 크게 중요하지 않음 (palloc이 다시 호출될 것이므로)
}

/* * 새로운 물리 프레임을 할당받아 반환하는 함수.
 * palloc_get_page(PAL_USER)를 사용합니다.
 */
struct frame *
allocate_frame (enum palloc_flags flags)
{
    void *kpage = palloc_get_page (flags);
    
    // 메모리가 부족한 경우 (Eviction이 필요한 시점)
    while (kpage == NULL) {
        vm_evict_frame();
        kpage = palloc_get_page(flags);
    }

    // 프레임 구조체 할당 (Kernel Heap)
    struct frame *frame = malloc (sizeof (struct frame));
    if (frame == NULL) {
        // 구조체 할당 실패 시, 가져온 페이지도 다시 반환
        palloc_free_page (kpage);
        return NULL;
    }

    // 프레임 정보 설정
    frame->kpage = kpage;
    frame->t = thread_current (); // 현재 스레드가 소유자
    frame->vme = NULL;            // 아직 매핑된 vme는 없음 (Caller가 설정 즉 page.c/process.c에서)

    // 프레임 테이블에 추가
    add_frame_to_table (frame);

    return frame;
}

/* 할당된 프레임을 프레임 테이블 리스트에 추가 (Thread-safe) */
void
add_frame_to_table (struct frame *frame)
{
    lock_acquire (&frame_table_lock);
    list_push_back (&frame_table, &frame->elem);
    lock_release (&frame_table_lock);
}

/* 프레임 해제 함수 */
void
free_frame (struct frame *frame)
{
    lock_acquire (&frame_table_lock);
    if (clock_hand == &frame->elem) {
        clock_hand = list_next(clock_hand);
        if (clock_hand == list_end(&frame_table)) {
            clock_hand = list_begin(&frame_table);
        }
    }
    list_remove (&frame->elem);
    lock_release (&frame_table_lock);

    palloc_free_page (frame->kpage);
    free (frame);
}

void
free_frame_by_vaddr (void *vaddr)
{
  struct thread *curr = thread_current();

  // 1. 페이지 테이블에서 vaddr에 대응하는 물리 메모리 주소(커널 가상 주소, kpage)를 가져옴
  void *kpage = pagedir_get_page (curr->pagedir, vaddr);

  if (kpage == NULL) {
    return;
  }

  // 2. 전역 프레임 테이블에서 kpage에 해당하는 frame 구조체 찾기
    struct frame *target_frame = NULL;
    struct list_elem *e;

    lock_acquire (&frame_table_lock);
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e))
    {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->kpage == kpage)
        {
            target_frame = f;
            break; 
        }
    }
    lock_release (&frame_table_lock);

    // 3. 찾은 프레임 해제
    if (target_frame != NULL) {
        free_frame (target_frame);
    }
}