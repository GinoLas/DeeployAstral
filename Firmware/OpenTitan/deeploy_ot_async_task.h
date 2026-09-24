// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef DEEPLOY_OT_ASYNC_TASK_H_
#define DEEPLOY_OT_ASYNC_TASK_H_
#include <stddef.h>
#include <stdint.h>

#define DEEPLOY_OT_ASYNC_ABI 1

// Use this type for cl_task on PULP and for descriptor copies on OpenTitan.
// letter0 is a pointer to this object; letter1 retains the original flags.
typedef struct {
  void *src;
  void *dst;
  uint32_t size;
  uint32_t src_stride;
  uint32_t dst_stride;
  uint32_t repetitions;
  uint32_t size_1d;
  uint32_t transfer_id;
  uint32_t src_key;          // external tensor base (not a local ping/pong address)
  uint32_t dst_key;          // same external tensor base
  uint32_t completion_addr;  // zero selects legacy EU completion
  uint32_t completion_value;
} deeploy_ot_task_t;

#ifndef DEEPLOY_OT_HOST_TEST
_Static_assert(sizeof(void *) == 4, "Mailbox ABI requires RV32 pointers");
_Static_assert(offsetof(deeploy_ot_task_t, transfer_id) == 28, "Wrong descriptor prefix");
_Static_assert(offsetof(deeploy_ot_task_t, src_key) == 32, "Wrong external-base offset");
_Static_assert(offsetof(deeploy_ot_task_t, completion_addr) == 40, "Wrong completion offset");
_Static_assert(sizeof(deeploy_ot_task_t) == 48, "Wrong mailbox descriptor size");
#endif
#endif
