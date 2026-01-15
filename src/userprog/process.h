#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct thread* get_child_process_by_tid(tid_t child_tid);
void process_cleanup(void);

struct child_entry {
    tid_t tid;              // 자식의 TID
    int exit_status;        // 종료 상태
    bool load_success;      // 로드 성공 여부
    struct semaphore load_sema; // 로드 대기용
    struct semaphore exit_sema; // 종료 대기용
    struct list_elem elem;  // 부모의 children 리스트에 들어갈 element
};

/* 인자 전달을 위한 보조 구조체 */
struct execute_args {
    char *file_name;
    struct child_entry *entry;
};

#endif /* userprog/process.h */
