#include "buffer_cache.h"

#include "devices/block.h"
#include "devices/timer.h"

#include "threads/synch.h"
#include "threads/malloc.h"

#include "filesys/filesys.h"

#include "lib/debug.h"
#include "lib/string.h"

const uint32_t CACHE_SIZE_IN_SECTORS = 64;
const uint32_t FLUSH_PERIOD_IN_SECS = 60;

static struct cache_entry* cache_vec;
static struct syn_list_t lock_list;
int64_t last_flush_ticks = 0;

// TODO: save free map in RAM & never evict
// TODO: add synchronization
// TODO: should change every block_read/write() with bufcache_read/write()? Some work on blocks other than fs_device ....

struct cache_entry {
    block_sector_t sector;  
    void* data;             // NULL = not used
};

struct lock_entry {
    struct lock lock;
    block_sector_t sector;
    struct list_elem elem;
};

static void lock_sector(block_sector_t sector) {
    lock_acquire(&lock_list.lock);

    struct list_elem* e;
    struct lock_entry* entry;
    for (e = list_begin (&lock_list.list); e != list_end (&lock_list.list); e = list_next (e)) {
        entry = list_entry(e, struct lock_entry, elem);
        if (entry->sector == sector) {
            goto Finish;
        }
    }

    entry = (struct lock_entry*) malloc(sizeof(struct lock_entry));
    list_push_front(&lock_list.list, &entry->elem);
    entry->sector = sector;
    lock_init(&entry->lock);

    Finish:
    lock_release(&lock_list.lock);
    lock_acquire(&entry->lock);
}

static void unlock_sector(block_sector_t sector) {
    lock_acquire(&lock_list.lock);

    struct list_elem* e;
    for (e = list_begin (&lock_list.list); e != list_end (&lock_list.list); e = list_next (e)) {
        struct lock_entry* entry = list_entry(e, struct lock_entry, elem);
        if (entry->sector == sector) {
            lock_release(&entry->lock);
            lock_release(&lock_list.lock);
            return;
        }
    }
    // Lock must be present
    NOT_REACHED();
}

void buffer_cache_init(void) {
    cache_vec = calloc(sizeof(struct cache_entry) * CACHE_SIZE_IN_SECTORS, 1);
    list_init(&lock_list.list);
    lock_init(&lock_list.lock);
}

void buffer_cache_deinit(void) {
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        free(cache_vec[i].data);
    }
}

// TODO:
int buffer_cache_find(uint32_t sector) {
    lock_acquire(&lock_list.lock);
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        if (cache_vec[i].data != NULL && cache_vec[i].sector == sector) {
            lock_release(&lock_list.lock);
            return i;
        }
    }

    lock_release(&lock_list.lock);
    return -1;
}

// returns initialized free entry index from cache_vec
// does eviction if necessary
static int buffer_cache_evict_single(void) {
    lock_acquire(&lock_list.lock);

    // search for empty entry, if exists
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        if (cache_vec[i].data == NULL) {
            cache_vec[i].data = malloc(BLOCK_SECTOR_SIZE);
            lock_release(&lock_list.lock);
            return i;
        }
    }

    // Eviction uses cyclic algorithm
    static int evict_idx = 0;
    evict_idx = (evict_idx+1) % CACHE_SIZE_IN_SECTORS;
    lock_release(&lock_list.lock);

    lock_sector(cache_vec[evict_idx].sector);    
    block_write(fs_device, cache_vec[evict_idx].sector, cache_vec[evict_idx].data);
    unlock_sector(cache_vec[evict_idx].sector);

    return evict_idx;
}

void buffer_cache_read(block_sector_t sector, void* data, off_t size, off_t offset) {
    ASSERT (offset + size <= BLOCK_SECTOR_SIZE);
    lock_sector(sector);

    int entry_idx = buffer_cache_find(sector);
    if (entry_idx == -1) {
        entry_idx = buffer_cache_evict_single();
        cache_vec[entry_idx].sector = sector;
                
        block_read(fs_device, sector, cache_vec[entry_idx].data);
    }
    memcpy(data, cache_vec[entry_idx].data + offset, size);

    unlock_sector(sector);
}

void buffer_cache_write(block_sector_t sector, const void* data, off_t size, off_t offset) {
    ASSERT (offset + size <= BLOCK_SECTOR_SIZE);
    lock_sector(sector);

    int entry_idx = buffer_cache_find(sector);
    if (entry_idx == -1) {
        entry_idx = buffer_cache_evict_single();
        
        cache_vec[entry_idx].sector = sector;
        block_read(fs_device, sector, cache_vec[entry_idx].data);
        
    } 

    memcpy(cache_vec[entry_idx].data + offset, data, size);
    block_write(fs_device, sector, cache_vec[entry_idx].data);

    unlock_sector(sector);
}


// Note: should pass all tests without periodic flush [I think]
bool buffer_cache_timeout(int64_t ticks) {
    if (ticks >= last_flush_ticks + FLUSH_PERIOD_IN_SECS * TIMER_FREQ)
        return true;
    return false;
}

void buffer_cache_full_flush(void) {
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        if (cache_vec[i].data == NULL)
            continue;
            
        block_write (fs_device, cache_vec[i].sector, cache_vec[i].data);
    }
    // update last full_flush time
    last_flush_ticks = timer_ticks();
}


// TODO: remove
int buffer_cache_test() {
    int i = 7;
    return i;
}