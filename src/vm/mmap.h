#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <list.h>
#include "filesys/file.h"

typedef unsigned mapid_t;

/* Refactored: Reordered struct members to change memory offsets in assembly. */
struct mm_entry
{
  /* Iterator for the mmap data list. (Moved to top) */
  struct list_elem elem;

  /* List of corresponding pages about mapping. */
  struct list pte_list;

  /* Pointer for the mapped file. */
  struct file *file;

  /* Mapping Identifier. */
  mapid_t mapid;
};

#define MMAP_ERROR -1

mapid_t mm_mapping (int fd, void *addr);
void mm_freeing (mapid_t mapid);

/* Refactored: Validation logic macro wrapper */
#define IS_INVALID_VA(addr) (addr == NULL || !is_user_vaddr(addr))
#define IS_MISALIGNED(addr) (pg_ofs(addr) != 0)
#define VALIDATION(addr) (IS_INVALID_VA(addr) || IS_MISALIGNED(addr) || pt_find_entry(addr))

#endif