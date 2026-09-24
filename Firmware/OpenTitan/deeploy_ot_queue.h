// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef DEEPLOY_OT_QUEUE_H_
#define DEEPLOY_OT_QUEUE_H_
#include <stdbool.h>
#include "deeploy_ot_async_task.h"
#ifndef OT_QUEUE_DEPTH
#define OT_QUEUE_DEPTH 8u
#endif
_Static_assert(OT_QUEUE_DEPTH > 0, "Queue cannot be empty");

typedef struct {
  uint32_t letter0;
  uint32_t flags;
  deeploy_ot_task_t task;
} ot_request_t;

typedef struct {
  ot_request_t slots[OT_QUEUE_DEPTH];
  volatile uint32_t head;
  volatile uint32_t tail;
  volatile uint32_t count;
} ot_queue_t;

// Single-core ISR/main-loop queue. Caller MUST mask interrupts around main-loop
// operations; ISR never nests. The payload is copied before publishing count.
static inline bool ot_queue_push(ot_queue_t *q, const ot_request_t *request) {
  if (q->count == OT_QUEUE_DEPTH) return false;
  q->slots[q->tail] = *request;
  q->tail = (q->tail + 1u) % OT_QUEUE_DEPTH;
  q->count++;
  return true;
}
static inline bool ot_queue_pop(ot_queue_t *q, ot_request_t *request) {
  if (q->count == 0) return false;
  *request = q->slots[q->head];
  q->head = (q->head + 1u) % OT_QUEUE_DEPTH;
  q->count--;
  return true;
}
#endif
