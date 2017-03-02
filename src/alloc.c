/*
 * Copyright (C) 2014, National ICT Australia Limited. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * The name of National ICT Australia Limited nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "platform.h"
#include "tcg.h"
#include "exception.h"
#include "util.h"
#include "alloc.h"

#define KB 1024
BYTE heap[8 * KB] = {0};

struct mem_node {
  UINT32 size; /* size of this data, in blocks */
  struct mem_node *next;
};
struct mem_node *prev = NULL;

#define BLOCK_SIZE sizeof(struct mem_node)

void *alloc(UINT32 size) {
  ASSERT(size > 0);
  if (!prev) {
    prev = (struct mem_node *)heap;
    *prev = (struct mem_node){.size = (sizeof(heap) / BLOCK_SIZE) - 1,
                              .next = NULL};
  }

  if (prev->size < size)
    return NULL;

  UINT32 blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
  struct mem_node *current = (struct mem_node *)(prev + blocks + 1);
  *current = (struct mem_node){.size = prev->size - (blocks + 1), .next = NULL};
  *prev = (struct mem_node){.size = size, .next = current};
  void *ret = (void *)(prev + 1);
  prev = current;
  return ret;
}
