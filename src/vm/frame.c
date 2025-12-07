/* vm/frame.c */
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include <list.h>

// 전역 프레임 테이블 (모든 활성 프레임을 관리)
static struct list frame_table;
// 프레임 테이블 접근을 보호하기 위한 락
static struct lock frame_table_lock;

/* 프레임 테이블 초기화 */
void
vm_frame_init (void)
{
    list_init (&frame_table);
    lock_init (&frame_table_lock);
}

/* * 새로운 물리 프레임을 할당받아 반환하는 함수.
 * palloc_get_page(PAL_USER)를 사용합니다.
 */
struct frame *
allocate_frame (enum palloc_flags flags)
{
    void *kpage = palloc_get_page (flags);
    
    // 메모리가 부족한 경우 (Eviction이 필요한 시점)
    if (kpage == NULL) {
        // TODO: 나중에 여기에 swap_out (eviction) 로직을 구현해야 합니다.
        // 현재는 구현되지 않았으므로 PANIC 처리하거나 NULL 반환
        // kpage = evict_frame(); 
        PANIC ("Frame allocation failed: Memory full (Swap not implemented)");
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
    frame->vme = NULL;                 // 아직 매핑된 vme는 없음 (Caller가 설정 즉 page.c/process.c에서)

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
    list_remove (&frame->elem);
    lock_release (&frame_table_lock);

    palloc_free_page (frame->kpage);
    free (frame);
}