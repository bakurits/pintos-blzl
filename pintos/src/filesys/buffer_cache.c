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
int64_t last_flush_ticks = 0;

// TODO: save free map in RAM & never evict
// TODO: add synchronization

struct cache_entry {
    block_sector_t sector;  
    void* data;             // NULL = not used
    struct lock lock;       
};


void buffer_cache_init(void) {
    cache_vec = calloc(sizeof(struct cache_entry) * CACHE_SIZE_IN_SECTORS, 1);
    
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        lock_init(&cache_vec[i].lock);
    }
}

void buffer_cache_deinit(void) {
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        free(cache_vec[i].data);
    }
}

// TODO:
int buffer_cache_find(uint32_t sector) {
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        if (cache_vec[i].data != NULL && cache_vec[i].sector == sector) {
            return i;
        }
    }
    return -1;
}

// returns initialized free entry from cache_vec
// does eviction if necessary
static int buffer_cache_evict_single(void) {
    // search for empty entry, if exists
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        if (cache_vec[i].data == NULL) {
            cache_vec[i].data = malloc(BLOCK_SECTOR_SIZE);
            return i;
        }
    }

    // always evict 0th / TODO: make it better
    int evict_idx = 0;
    block_write(fs_device, cache_vec[evict_idx].sector, cache_vec[evict_idx].data);
    return evict_idx;
}

void buffer_cache_read(uint32_t sector, void* data, off_t size, off_t offset) {
    ASSERT (offset + size <= BLOCK_SECTOR_SIZE);
    
    int entry_idx = buffer_cache_find(sector);
    if (entry_idx == -1) {
        entry_idx = buffer_cache_evict_single();
        cache_vec[entry_idx].sector = sector;
        block_read(fs_device, sector, cache_vec[entry_idx].data);
    }

    memcpy(data, cache_vec[entry_idx].data + offset, size);
}

void buffer_cache_write(uint32_t sector, const void* data, off_t size, off_t offset) {
    ASSERT (offset + size <= BLOCK_SECTOR_SIZE);
    
    int entry_idx = buffer_cache_find(sector);
    if (entry_idx == -1) {
        entry_idx = buffer_cache_evict_single();
        cache_vec[entry_idx].sector = sector;
        block_read(fs_device, sector, cache_vec[entry_idx].data);
    } 

    memcpy(cache_vec[entry_idx].data + offset, data, size);
    block_write(fs_device, sector, cache_vec[entry_idx].data);
}



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