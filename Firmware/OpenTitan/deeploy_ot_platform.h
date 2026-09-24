// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef DEEPLOY_OT_PLATFORM_H_
#define DEEPLOY_OT_PLATFORM_H_
#include <stdint.h>
static inline void ot_fence(void) {
  __asm__ volatile ("fence iorw, iorw" ::: "memory");
}
static inline uint32_t ot_irq_save(void) {
  uint32_t state;
  __asm__ volatile ("csrrc %0, mstatus, %1" : "=r"(state) : "r"(8u) : "memory");
  return state;
}
static inline void ot_irq_restore(uint32_t state) {
  if (state & 8u) __asm__ volatile ("csrsi mstatus, 8" ::: "memory");
}
static inline void ot_cpu_idle(void) {
  __asm__ volatile ("wfi" ::: "memory");
}
#endif
