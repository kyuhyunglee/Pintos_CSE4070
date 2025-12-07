// vm/frame.h
#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "vm/page.h" // 여기서 vm_entry를 정의 - vaddr를 참조하는데 쓰인다
#include "threads/thread.h"
#include "threads/palloc.h"

// 프레임 테이블 엔트리 구조체
struct frame {
    void *kpage;

    struct vm_entry *vme; // 이 프레임에 매핑된 가상 페이지(역참조용)

    struct thread *t; // 이 프레임을 소유한 스레드

    struct list_elem elem; // 프레임 테이블을 위한 리스트 엘림
};

void vm_frame_init(void);
struct frame *allocate_frame(enum palloc_flags flags);
void free_frame(struct frame *frame);
void add_frame_to_table(struct frame *frame);

#endif