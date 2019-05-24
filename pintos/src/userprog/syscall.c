#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"


static struct lock syscall_lock;
static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&syscall_lock);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args);
static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args);

typedef void (*syscall_func_t)(struct intr_frame *f UNUSED, uint32_t *args);

syscall_func_t syscall_func_arr[14] = {
    syscall_halt,   syscall_exit,    syscall_exec, syscall_wait,
    syscall_create, syscall_remove,  syscall_open, syscall_filesize,
    syscall_read,   syscall_write,   syscall_seek, syscall_tell,
    syscall_close,  syscall_practice};

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);
  printf("System call number: %d\n", args[0]);

  syscall_func_arr[args[0]](f, args);
}

static void syscall_halt(struct intr_frame *f UNUSED, uint32_t *args) {
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f UNUSED, uint32_t *args) {
  f->eax = args[1];
  printf("%s: exit(%d)\n", &thread_current()->name, args[1]);
  thread_exit();
  struct child_info *child = get_child_info(thread_current());
  if (child != NULL) {
    child->status = args[1];
  }
}

static void syscall_exec(struct intr_frame *f UNUSED, uint32_t *args) {
	lock_acquire (&syscall_lock);
	__pid_t process_pid =  process_execute ((char*)args[1]);
	f->eax = process_pid;
	if (process_pid != TID_ERROR) {
		process_exit ();
	}

	lock_release (&syscall_lock);
}

static void syscall_wait(struct intr_frame *f UNUSED, uint32_t *args) {
  __pid_t pid = args[1];
  struct child_info *child = get_child_info(thread_current());
  if (child == NULL) {
    f->eax = -1;
    return;
  }
  sema_down(&child->sema);
  f->eax = child->status;
  thread_remove_child(child->child_thread);
}

static void syscall_create(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_remove(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_open(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_filesize(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_read(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_write(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_seek(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_tell(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_close(struct intr_frame *f UNUSED, uint32_t *args) {}

static void syscall_practice(struct intr_frame *f UNUSED, uint32_t *args) {
  f->eax = args[1] + 1;
}
