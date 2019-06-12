#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Initialize
void buffer_cache_init(void);
void buffer_cache_deinit(void);

bool buffer_cache_contains(uint32_t sector);
int buffer_cache_save(uint32_t sector, const void* data);
int buffer_cache_load(uint32_t sector, void* data);

// Flushes all in memory sectors to disk 
// (For periodical flushing)
void buffer_cache_full_flush(void);

int buffer_cache_test(void);