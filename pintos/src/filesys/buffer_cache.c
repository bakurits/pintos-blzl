#include "buffer_cache.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "lib/debug.h"

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
bool buffer_cache_contains(uint32_t sector UNUSED) {return true;}
int buffer_cache_save(uint32_t sector UNUSED, const void* data UNUSED) {return 1;}
int buffer_cache_load(uint32_t sector UNUSED, void* data UNUSED) {return 1;}

void buffer_cache_full_flush(void) {}

static void buffer_cache_evict(uint8_t idx UNUSED) {}


int buffer_cache_test() {
    int i = 7;
    return i;
}