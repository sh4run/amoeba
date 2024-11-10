/*
 * mempool.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#ifndef __MEMPOOL_H__
#define __MEMPOOL_H__

#include <stdint.h>

#define MAX_BUFFER_FACTOR   6

extern int mempool_init (uint32_t memory_cap);
extern void *mempool_alloc (int *size);
extern void mempool_free (void *mem);
extern void mempool_output_stats (void);

#endif
