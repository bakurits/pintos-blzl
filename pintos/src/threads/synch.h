#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
    unsigned value;             /* Current value. */
    int max_priority;           /* Maximum thread priority */
    struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock {
    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */

	struct list_elem elem;		/* To link all acquired locks of a thread */
};

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition {
    struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);


/* Reader-Writer lock */
struct rw_lock {
    struct lock r_lock;
    struct lock w_lock;
    int waiters;
};

void rw_lock_init(struct rw_lock*);
void rw_read_lock(struct rw_lock*);
void rw_read_unlock(struct rw_lock*);
void rw_write_lock(struct rw_lock*);
void rw_write_unlock(struct rw_lock*);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
