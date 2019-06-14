#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "filesys/off_t.h"

// Initialize
void buffer_cache_init(void);
void buffer_cache_deinit(void);

int buffer_cache_find(uint32_t sector); // found? idx : -1

// Must operate on a SINGLE sector <=> offset+size < BLOCK_SECTOR_SIZE
void buffer_cache_write(uint32_t sector, const void* data, off_t size, off_t offset);
void buffer_cache_read(uint32_t sector, void* data, off_t size, off_t offset);

// Flushes all in memory sectors to disk 
// (For periodical flushing)
void buffer_cache_full_flush(void);
// Returns true if full_flush is required
// (Automatic flush period passed)
bool buffer_cache_timeout(int64_t ticks);

int buffer_cache_test(void);