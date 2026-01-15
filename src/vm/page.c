// vm/page.c
#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <hash.h>

// vaddr 기반 해시 값 생성
static unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
    const struct vm_entry *vme = hash_entry (p_, struct vm_entry, elem);
    return hash_bytes (&vme->vaddr, sizeof vme->vaddr);
}

static bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    const struct vm_entry *a = hash_entry (a_, struct vm_entry, elem);
    const struct vm_entry *b = hash_entry (b_, struct vm_entry, elem);

    return a->vaddr < b->vaddr;
}

static void
page_action (struct hash_elem *e, void *aux UNUSED)
{
    struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
    struct thread *t = thread_current();

    if (vme->is_loaded) {
        // 1. 물리 프레임 해제 (palloc_free_page 포함)
        free_frame_by_vaddr(vme->vaddr);
        
        // 매핑을 지워야 process_exit의 pagedir_destroy가 중복 해제를 하지 않음
        pagedir_clear_page(t->pagedir, vme->vaddr); 
    }
    
    // vme 해제
    free (vme);
}

/* Supplemental Page Table 초기화 */
void
vm_init (struct hash *vm)
{
    // hash_init(해시테이블, 해시함수, 비교함수, 보조데이터)
    hash_init (vm, page_hash, page_less, NULL);
}

/* Supplemental Page Table 파괴 */
void
vm_destroy (struct hash *vm)
{
    /* [해결] 여기서 page_action을 사용해야 경고가 사라짐 */
    hash_destroy (vm, page_action);
}

struct vm_entry *
find_vme (void *vaddr)
{
    struct thread *t = thread_current();
    // vaddr을 포함한 더미 vm_entry 생성 (검색용)
    struct vm_entry p;
    p.vaddr = pg_round_down (vaddr); // 페이지 시작 주소로 정렬

    struct hash_elem *e = hash_find (&t->vm, &p.elem);

    return e != NULL ? hash_entry (e, struct vm_entry, elem) : NULL;
}

/* vm_entry를 SPT에 삽입 */
bool
insert_vme (struct hash *vm, struct vm_entry *vme)
{
    // hash_insert는 중복된 항목이 없으면 NULL 반환, 있으면 기존 항목 반환
    return hash_insert (vm, &vme->elem) == NULL;
}

/* vm_entry를 SPT에서 삭제 */
bool
delete_vme (struct hash *vm, struct vm_entry *vme)
{
    if (hash_delete (vm, &vme->elem) != NULL) {
        free (vme);
        return true;
    }
    return false;
}