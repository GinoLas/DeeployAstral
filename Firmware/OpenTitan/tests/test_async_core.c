// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// Host tests for the actual queue and byte-exact CTR copy algorithm.
#define DEEPLOY_OT_HOST_TEST 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../deeploy_ot_queue.h"
#include "../deeploy_ot_ctr_copy.h"

static void test_queue(void) {
  ot_queue_t queue = {0};
  ot_request_t request = {0}, out;
  assert(!ot_queue_pop(&queue, &out));
  for (unsigned round = 0; round < 100; ++round) {
    for (unsigned i = 0; i < OT_QUEUE_DEPTH; ++i) {
      request.flags = i;
      request.task.size = 1000 + i;
      request.task.completion_value = round * OT_QUEUE_DEPTH + i;
      assert(ot_queue_push(&queue, &request));
      request.task.size = 0; // queue must own a COPY
    }
    assert(!ot_queue_push(&queue, &request)); // no overwrite when full
    for (unsigned i = 0; i < OT_QUEUE_DEPTH; ++i) {
      assert(ot_queue_pop(&queue, &out));
      assert(out.flags == i && out.task.size == 1000 + i);
      assert(out.task.completion_value == round * OT_QUEUE_DEPTH + i);
    }
    assert(!ot_queue_pop(&queue, &out));
  }
}

typedef struct {
  unsigned char source[128], destination[128];
  uint32_t first, limit, write_first, write_limit, read_count, write_count, counter;
} memory_t;
static void read_bytes(void *ctx, uint32_t src, uint8_t *out, uint32_t n) {
  memory_t *m = ctx;
  assert(n > 0 && n <= 16 && src >= m->first && src + n <= m->limit);
  memcpy(out, m->source + src, n);
  m->read_count += n;
}
static void write_bytes(void *ctx, uint32_t dst, const uint8_t *in, uint32_t n) {
  memory_t *m = ctx;
  assert(n > 0 && n <= 16 && dst >= m->write_first && dst + n <= m->write_limit);
  memcpy(m->destination + dst, in, n);
  m->write_count += n;
}
static uint8_t stream(uint32_t offset) {
  return (uint8_t)((offset * 37u + 19u) ^ (offset >> 3u));
}
static void block(void *ctx, const uint8_t in[16], uint8_t out[16]) {
  memory_t *m = ctx;
  // Deterministic CTR keystream stand-in. This tests counter offsets and exact
  // byte bounds, NOT the AES hardware or cryptographic implementation.
  for (unsigned i = 0; i < 16; ++i) out[i] = in[i] ^ stream(m->counter * 16u + i);
  m->counter++;
}
static void test_partial_transfers(void) {
  for (uint32_t offset = 0; offset < 64; ++offset) {
    for (uint32_t size = 0; size <= 65; ++size) {
      memory_t m = {.first = 5, .limit = 5 + size, .write_first = 7,
                    .write_limit = 7 + size, .counter = offset / 16u};
      for (unsigned i = 0; i < sizeof(m.source); ++i) m.source[i] = (uint8_t)i;
      memset(m.destination, 0xA5, sizeof(m.destination));
      const ot_ctr_io_t io = {read_bytes, write_bytes, block, &m};
      ot_ctr_copy(&io, 5, 7, size, offset);
      assert(m.read_count == size && m.write_count == size);
      for (uint32_t i = 0; i < size; ++i)
        assert(m.destination[7 + i] == (uint8_t)(m.source[5 + i] ^ stream(offset + i)));
      for (unsigned i = 0; i < sizeof(m.destination); ++i)
        if (i < 7 || i >= 7 + size) assert(m.destination[i] == 0xA5);
    }
  }
}
int main(void) {
  test_queue();
  test_partial_transfers();
  puts("PASS: queue snapshots/FIFO/full/wrap and 4224 byte-exact CTR copy cases");
  return 0;
}
