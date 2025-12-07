// vm/page.h
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/palloc.h"
#include "filesys/off_t.h"

enum vm_type {
    VM_BIN,      // Binary code
    VM_FILE,     // File-backed
    VM_ANON      // Anonymous (swap-backed)
};

// 가상 메모리 엔트리 구조체
struct vm_entry {
    uint8_t type;          // vm_type-요구서에서 잘 구분하라고 써짐
    void *vaddr;          // 가상 주소
    bool writable;        // 쓰기 가능 여부
    bool is_loaded;       // 메모리에 로드되었는지 여부

    struct file *file ;   // 매핑된 파일 포인터
    off_t offset;        // 파일 내 오프셋
    size_t read_bytes;   // 파일에서 읽을 바이트 수
    size_t zero_bytes;   // 0으로 채울 바이트 수

    size_t swap_slot;    // 스왑 슬롯 인덱스

    struct hash_elem elem; // 해시 테이블 엘림
};

void vm_init (struct hash *vm);
void vm_destroy (struct hash *vm);

struct vm_entry *find_vme (void *vaddr);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

#endif /* vm/page.h */