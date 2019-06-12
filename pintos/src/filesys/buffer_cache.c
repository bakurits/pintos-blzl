#include "buffer_cache.h"

#include "devices/block.h"

#include "threads/synch.h"
#include "threads/malloc.h"

#include "filesys/filesys.h"

#include "lib/debug.h"
#include "lib/string.h"

const uint32_t CACHE_SIZE_IN_SECTORS = 64;
static struct cache_entry* cache_vec;

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
int buffer_cache_find(uint32_t sector UNUSED) {
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


void buffer_cache_write(uint32_t sector, const void* data, off_t size, off_t offset) {
   int entry_idx = buffer_cache_find(sector);
   if (entry_idx == -1) {
       entry_idx = buffer_cache_evict_single();
       cache_vec[entry_idx].sector = sector;
   } 

   memcpy(cache_vec[entry_idx].data+offset, data+offset, size);
}

void buffer_cache_read(uint32_t sector, void* data, off_t size, off_t offset) {
    int entry_idx = buffer_cache_find(sector);
    if (entry_idx == -1) {
        entry_idx = buffer_cache_evict_single();
        block_read(fs_device, sector, cache_vec[entry_idx].data);
    }

    memcpy(data, cache_vec[entry_idx].data + offset, size);
}

void buffer_cache_full_flush(void) {
    unsigned int i;
    for (i=0; i<CACHE_SIZE_IN_SECTORS; i++) {
        block_write (fs_device, cache_vec[i].sector, cache_vec[i].data);
    }
}


// TODO: remove
int buffer_cache_test() {
    int i = 7;
    return i;
}