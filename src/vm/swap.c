#include "vm/swap.h"
#include "devices/block.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

/* 페이지 하나당 필요한 디스크 섹터 수 (4096 / 512 = 8) */
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;

/* 스왑 영역 사용 여부를 관리하는 비트맵 */
static struct bitmap *swap_bitmap;

/* 스왑 파티션 블록 장치 */
static struct block *swap_block;

/* 동기화를 위한 락 */
static struct lock swap_lock;

/* 스왑 시스템 초기화 */
void
swap_init (void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    PANIC ("Error: Can't initialize swap block");

  swap_bitmap = bitmap_create (block_size (swap_block) / SECTORS_PER_PAGE);
  if (swap_bitmap == NULL)
    PANIC ("Error: Can't create swap bitmap");

  /* 모든 비트를 0으로 초기화한 뒤 */
  bitmap_set_all (swap_bitmap, false);
  
  /* [수정됨] 0번 인덱스는 '스왑 없음'을 의미하는 0과 혼동되므로 사용하지 않음 */
  bitmap_set(swap_bitmap, 0, true);

  lock_init (&swap_lock);
}

/* Swap Out: 메모리 -> 디스크 */
size_t
swap_out (void *kpage)
{
  lock_acquire (&swap_lock);

  /* 빈 스왑 슬롯 찾기 (true: 찾으면 비트를 1로 설정함) */
  size_t swap_index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);

  if (swap_index == BITMAP_ERROR)
    PANIC ("Error: Swap partition is full!");

  /* 8개의 섹터에 걸쳐서 페이지 내용을 씀 */
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
      block_write (swap_block,
                   swap_index * SECTORS_PER_PAGE + i,
                   (uint8_t *) kpage + i * BLOCK_SECTOR_SIZE);
    }

  lock_release (&swap_lock);

  return swap_index;
}

/* Swap In: 디스크 -> 메모리 */
void
swap_in (size_t swap_index, void *kpage)
{
  lock_acquire (&swap_lock);

  /* 해당 슬롯이 사용 중인지 확인 (방어적 코딩) */
  if (bitmap_test (swap_bitmap, swap_index) == false)
    PANIC ("Error: Swap slot is empty, cannot swap in");

  /* 8개의 섹터를 읽어서 메모리에 복원 */
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
    {
      block_read (swap_block,
                  swap_index * SECTORS_PER_PAGE + i,
                  (uint8_t *) kpage + i * BLOCK_SECTOR_SIZE);
    }

  /* 다 읽었으면 해당 슬롯을 비움 (false로 설정) */
  bitmap_set (swap_bitmap, swap_index, false);

  lock_release (&swap_lock);
}
