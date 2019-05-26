#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "process.h"

void syscall_init(void);

int _practice(int i);
void _halt(void);
void _exit(int status);
pid_t _exec(const char *cmd_line);
int _wait(pid_t pid);
bool _create(const char *file, unsigned initial_size);
bool _remove(const char *file);
int _open(const char *file);
int _filesize(int fd);
int _read(int fd, void *buffer, unsigned size);
int _write(int fd, const void *buffer, unsigned size);
void _seek(int fd, unsigned position);
unsigned _tell(int fd);
void _close(int fd);

#endif /* userprog/syscall.h */