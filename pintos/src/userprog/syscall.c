#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_practice (struct intr_frame *f UNUSED, uint32_t practice_val) {
	f->eax = practice_val + 1;
}

static void syscall_exit (struct intr_frame *f UNUSED, uint32_t exit_status) {
    f->eax = exit_status;
    printf("%s: exit(%d)\n", &thread_current()->name, exit_status);
    thread_exit();
}

static void syscall_handler(struct intr_frame *f UNUSED) {
  uint32_t *args = ((uint32_t *)f->esp);
  printf("System call number: %d\n", args[0]);
  switch (args[0]) {
    case SYS_EXIT:
			syscall_exit (f, args[1]);
      break;

		case SYS_PRACTICE:
			syscal_practice (f, args[1]);
			break;
  }
}
