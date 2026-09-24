// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// Included by firmware_async.c after the board-specific AES/HMAC helpers.
#include "deeploy_ot_queue.h"
#include "deeploy_ot_ctr_copy.h"

#ifndef OT_CLUSTER_ALIAS_BASE
#define OT_CLUSTER_ALIAS_BASE CLUSTER_SPM_BASE_ADDR
#endif
// Preserves the CPU-side TCDM word spacing used by the supplied firmware.
// DMA addresses remain byte addresses in the iDMA address space.
#ifndef OT_TCDM_CPU_WORD_STRIDE
#define OT_TCDM_CPU_WORD_STRIDE 4u
#endif
#define OT_MAILBOX_IRQ 159u

static ot_queue_t ot_queue;
static bool ot_deferred;
static uint32_t ot_deferred_letter0, ot_deferred_flags;

#include "deeploy_ot_platform.h"
static uint32_t ot_global_addr(uint32_t addr) {
  return addr < 0x50000000u ? addr + OT_CLUSTER_ALIAS_BASE : addr;
}
static _Noreturn void ot_fail(const char *reason) {
  (void)ot_irq_save();
  printf("[OT] Fatal: %s. No completion published.\r\n", reason);
  for (;;) ot_cpu_idle();
}
static void ot_require(bool condition, const char *reason) {
  if (!condition) ot_fail(reason);
}
static bool ot_is_control(uint32_t flags) {
  return (flags & (HOST_MASK | END_MASK | INIT_MASK | HMAC_MASK | IV_MASK)) != 0;
}

// Called either from the non-nesting ISR or with interrupts masked in main.
static void ot_accept(uint32_t letter0, uint32_t flags) {
  ot_request_t request = {.letter0 = letter0, .flags = flags};
  bool no_descriptor = (flags & (HOST_MASK | END_MASK)) != 0 ||
                       ((flags & INIT_MASK) && ((flags & CLEAR_MASK) || letter0 == 0));
  if (!no_descriptor) {
    ot_require(letter0 != 0, "null descriptor");
    ot_require((letter0 & 3u) == 0, "unaligned descriptor");
    // Controls need only the original 32-byte prefix, never completion fields.
    size_t bytes = ot_is_control(flags) ? offsetof(deeploy_ot_task_t, src_key) : sizeof(request.task);
    volatile const uint8_t *shared = (volatile const uint8_t *)(uintptr_t)ot_global_addr(letter0);
    uint8_t *copy = (uint8_t *)&request.task;
    ot_fence();
    for (size_t i = 0; i < bytes; ++i) copy[i] = shared[i];
  }
  ot_require(ot_queue_push(&ot_queue, &request), "internal queue overflow");
  ot_fence();
  mb_write(0x1, MBOX_CAR_INT_RCV_CLR(1));
  mb_write(0x1, MBOX_CAR_INT_SND_CLR(1)); // ACK only AFTER private copy
  ot_fence();
}

void external_irq_handler(void) {
  uint32_t iid = *PLIC_CLAIM_COMPLETE;
  if (iid == 0) return;
  if (iid == OT_MAILBOX_IRQ) {
    uint32_t letter0, flags;
    mailbox_read(1, &letter0, &flags);  // read BEFORE clearing mailbox state
    if (ot_queue.count == OT_QUEUE_DEPTH) {
      // Sender keeps descriptor immutable until SND_CLR. Clear only the receive
      // interrupt to prevent an interrupt storm; main admits this message later.
      ot_require(!ot_deferred, "multiple deferred mailbox messages");
      ot_deferred_letter0 = letter0;
      ot_deferred_flags = flags;
      ot_deferred = true;
      mb_write(0x1, MBOX_CAR_INT_RCV_CLR(1));
    } else {
      ot_accept(letter0, flags);
    }
  }
  ot_fence();
  *PLIC_CLAIM_COMPLETE = iid;
}

static void ot_dma_copy(uint32_t src, uint32_t dst, uint32_t size) {
  if (size == 0) return;
  int ticket = idma_issue_1d(src, dst, size);
  wait_for_idma_eot(ticket);
  ot_fence();
}
static void ot_scratch_read(void *ctx, uint32_t src, uint8_t *out, uint32_t n) {
  (void)ctx;
  ot_dma_copy(src, TCDM_BASE, n);
  volatile uint32_t *scratch = (volatile uint32_t *)TCDM_BASE;
  for (uint32_t i = 0; i < n; ++i)
    out[i] = (uint8_t)(scratch[(i / 4u) * OT_TCDM_CPU_WORD_STRIDE] >> (8u * (i % 4u)));
}
static void ot_scratch_write(void *ctx, uint32_t dst, const uint8_t *in, uint32_t n) {
  (void)ctx;
  volatile uint32_t *scratch = (volatile uint32_t *)TCDM_BASE;
  for (uint32_t word = 0; word < (n + 3u) / 4u; ++word) {
    uint32_t value = 0;
    for (uint32_t byte = 0; byte < 4u && word * 4u + byte < n; ++byte)
      value |= (uint32_t)in[word * 4u + byte] << (8u * byte);
    scratch[word * OT_TCDM_CPU_WORD_STRIDE] = value;
  }
  ot_fence();
  ot_dma_copy(TCDM_BASE, dst, n);
}
static void ot_aes_block(void *ctx, const uint8_t in[16], uint8_t out[16]) {
  (void)ctx;
  mmio_region_t aes = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR);
  while (!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_INPUT_READY_BIT)) {}
  for (uint32_t i = 0; i < 4u; ++i) {
    uint32_t word;
    memcpy(&word, in + 4u * i, 4);
    mmio_region_write32(aes, _aes_get_datainreg(i), word);
  }
  while (!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_OUTPUT_VALID_BIT)) {}
  for (uint32_t i = 0; i < 4u; ++i) {
    uint32_t word = mmio_region_read32(aes, AES_DATA_OUT_0_REG_OFFSET + 4u * i);
    memcpy(out + 4u * i, &word, 4);
  }
}
static void ot_secure_copy(uint32_t src, uint32_t dst, uint32_t n,
                           uint32_t offset, const uint32_t base_iv[4], uint32_t aes_key[8]) {
  uint32_t iv[4];
  memcpy(iv, base_iv, sizeof(iv));
  // Retains the supplied firmware's counter/word convention, including weights.
  add_u128_leword_visual(iv, offset / 16u);
  aes_init(iv, aes_key);
  const ot_ctr_io_t io = {ot_scratch_read, ot_scratch_write, ot_aes_block, NULL};
  ot_ctr_copy(&io, src, dst, n, offset);
  ot_fence();
}

static void ot_data_transfer(const ot_request_t *request) {
  const deeploy_ot_task_t *task = &request->task;
  const uint32_t flags = request->flags;
  uint32_t src = ot_global_addr((uint32_t)(uintptr_t)task->src);
  uint32_t dst = ot_global_addr((uint32_t)(uintptr_t)task->dst);
  const bool two_dim = (flags & GEOMETRY_MASK) != 0;
  const bool decrypt = (flags & OPERATION_MASK) != 0;
  uint32_t rows = two_dim ? task->repetitions : 1;
  uint32_t bytes = two_dim ? task->size_1d : task->size;
  uint32_t src_stride = two_dim ? task->src_stride : 0;
  uint32_t dst_stride = two_dim ? task->dst_stride : 0;
  ot_require(rows != 0 && bytes != 0, "empty data transfer");
  ot_require((uint64_t)rows * bytes == task->size, "inconsistent 2D size");
  ot_require((uint64_t)src + (uint64_t)(rows - 1u) * src_stride + bytes <= UINT32_MAX,
             "source range overflow");
  ot_require((uint64_t)dst + (uint64_t)(rows - 1u) * dst_stride + bytes <= UINT32_MAX,
             "destination range overflow");
  ot_require(!two_dim || rows == 1 || (src_stride >= bytes && dst_stride >= bytes),
             "overlapping rows");

  uint32_t iv[4], aes_key[8], external_base = 0;
  if (flags & SECURE_MASK) {
    uint32_t supplied_base = decrypt ? task->src_key : task->dst_key;
    ot_require(supplied_base != 0, "missing external tensor base; rebuild PULP codegen");
    external_base = ot_global_addr(supplied_base);
    uint32_t external = decrypt ? src : dst;
    ot_require(external >= external_base, "external address precedes tensor base");
    if (!decrypt && external == external_base) {
      // A full tensor production starts at its base, independent of tile shape.
      // Renew IV AND key on every production, including repeated inference.
      utils_csrng_randgen(&key, TITANSSL_TEST_WORDSIZES);
      memcpy(iv, key.data, sizeof(iv));
      memcpy(aes_key, key.data + sizeof(iv), sizeof(aes_key));
      ot_require(hashmap_push_random(external_base, external_base, iv, aes_key) != HM_ERR_FULL,
                 "crypto metadata table full");
    } else {
      uint32_t origin = 0;
      ot_require(hashmap_get_random(external_base, &origin, iv, aes_key) == HM_TRUE,
                 "missing tensor IV/key (first output must start at tensor base)");
      ot_require(origin == external_base, "invalid crypto metadata origin");
    }
  }
  for (uint32_t row = 0; row < rows; ++row) {
    uint32_t row_src = src + row * src_stride;
    uint32_t row_dst = dst + row * dst_stride;
    if (flags & SECURE_MASK) {
      uint32_t external = decrypt ? row_src : row_dst;
      ot_secure_copy(row_src, row_dst, bytes, external - external_base, iv, aes_key);
    } else {
      ot_dma_copy(row_src, row_dst, bytes);
    }
  }
}

static void ot_complete(const ot_request_t *request) {
  ot_fence(); // all iDMA and AES work already drained by the worker
  if (!ot_is_control(request->flags) && request->task.completion_addr != 0) {
    uint32_t address = ot_global_addr(request->task.completion_addr);
    ot_require((address & 3u) == 0, "unaligned completion address");
    *(volatile uint32_t *)(uintptr_t)address = request->task.completion_value;
    ot_fence();
    return; // NO legacy EU event for asynchronous transfers
  }
  *(volatile uint32_t *)eu_evt_trig_cluster_addr(IDMA_EVENT) = 1u;
  ot_fence();
}

static void ot_execute(const ot_request_t *request) {
  uint32_t flags = request->flags;
  uint32_t src = ot_global_addr((uint32_t)(uintptr_t)request->task.src);
  uint32_t dst = ot_global_addr((uint32_t)(uintptr_t)request->task.dst);
  if (flags & HOST_MASK) {
    ot_fence();
    *(volatile uint32_t *)0x7800FF00 = 0xFFFFFFF0;
    ot_fence();
    pulp_cluster_kick_off((void *)(uintptr_t)request->letter0);
    return;
  }
  if (flags & END_MASK) {
    // FIFO ordering guarantees earlier transfers have fully completed.
    mailbox_send(7, request->letter0, flags);
    mb_write(0x1, MBOX_CAR_INT_SND_SET(7));
    hashmap_init();
    return;
  }
  if (flags & INIT_MASK) {
    if (flags & CLEAR_MASK) {
      hashmap_init(); // execute only with earlier requests drained
    } else {
      initialize_memory();
      utils_csrng_randgen(&key, TITANSSL_TEST_WORDSIZES);
      // InitNetwork also sends (letter0=0, flags=16): not a descriptor.
      if (request->letter0 != 0) {
        ot_require(request->task.src != NULL && request->task.dst != NULL, "null key pointer");
        memcpy(AesKey, (const void *)(uintptr_t)src, sizeof(AesKey));
        memcpy(kHmacKey, (const void *)(uintptr_t)dst, sizeof(kHmacKey));
      }
    }
  } else if (flags & HMAC_MASK) {
    dif_hmac_t hmac;
    test_setup(mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR), &hmac);
    ot_require(run_test(&hmac, (const char *)(uintptr_t)src, request->task.size,
                        (const uint8_t *)kHmacKey, (uint32_t *)(uintptr_t)dst) > 0,
               "HMAC verification failed");
  } else if (flags & IV_MASK) {
    uint32_t iv[4];
    memcpy(iv, (const void *)(uintptr_t)dst, sizeof(iv));
    ot_require(hashmap_push_random(src, src, iv, AesKey) != HM_ERR_FULL, "weight metadata table full");
  } else {
    ot_require((flags & ~0xFu) == 0, "unknown data flags");
    ot_data_transfer(request);
  }
  ot_complete(request);
}

static void ot_worker_run(void) {
  for (;;) {
    ot_request_t request;
    uint32_t state = ot_irq_save();
    bool have_request = ot_queue_pop(&ot_queue, &request);
    if (ot_deferred && ot_queue.count < OT_QUEUE_DEPTH) {
      ot_accept(ot_deferred_letter0, ot_deferred_flags);
      ot_deferred = false;
    }
    ot_irq_restore(state);
    if (have_request) ot_execute(&request);
    // Deliberate polling while idle: avoids a check-empty/WFI lost wakeup.
    // Interrupts remain enabled during all DMA/AES waits; ISR only enqueues.
  }
}
