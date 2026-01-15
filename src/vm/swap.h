#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>
#include "vm/page.h"

/* Swap 초기화 */
void swap_init (void);

/* 스왑 영역으로 페이지 내보내기 (Swap Out) 
   kpage의 내용을 스왑 디스크의 빈 슬롯에 저장하고, 슬롯 인덱스를 반환 */
size_t swap_out (void *kpage);

/* 스왑 영역에서 페이지 가져오기 (Swap In)
   swap_index 슬롯의 내용을 kpage로 읽어오고, 해당 슬롯을 비움 */
void swap_in (size_t swap_index, void *kpage);

#endif /* vm/swap.h */