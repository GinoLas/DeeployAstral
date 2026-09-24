// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
// Executes the actual service with mocked MMIO/iDMA/AES. No real crypto claim.
#define DEEPLOY_OT_HOST_TEST 1
#define DEEPLOY_OT_PLATFORM_H_ 1
#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif
#include "../deeploy_ot_async_task.h"

static void ot_fence(void) {}
static uint32_t ot_irq_save(void) { return 8; }
static void ot_irq_restore(uint32_t state) { (void)state; }
static jmp_buf fatal_jump;
static bool expect_fatal;
static void ot_cpu_idle(void) {
  if (expect_fatal) longjmp(fatal_jump, 1);
  abort();
}
#define CLUSTER_SPM_BASE_ADDR 0x50000000u
#define GEOMETRY_MASK 1u
#define WEIGHT_MASK 2u
#define OPERATION_MASK 4u
#define SECURE_MASK 8u
#define INIT_MASK 16u
#define CLEAR_MASK 32u
#define HMAC_MASK 64u
#define END_MASK 128u
#define IV_MASK 256u
#define HOST_MASK 0xFF000000u
#define TCDM_BASE 0x78010000u
#define TOP_EARLGREY_AES_BASE_ADDR 0u
#define TOP_EARLGREY_HMAC_BASE_ADDR 0u
#define AES_STATUS_REG_OFFSET 100u
#define AES_STATUS_INPUT_READY_BIT 0u
#define AES_STATUS_OUTPUT_VALID_BIT 1u
#define AES_DATA_OUT_0_REG_OFFSET 16u
#define IDMA_EVENT 0u
#define HM_ERR_FULL (-1)
#define HM_TRUE 1
#define TITANSSL_TEST_WORDSIZES 18u
#define MBOX_CAR_INT_RCV_CLR(x) (10u + (x))
#define MBOX_CAR_INT_SND_CLR(x) (20u + (x))
#define MBOX_CAR_INT_SND_SET(x) (30u + (x))
static uint32_t claim, eu_event, mb_letter0, mb_flags, acks, dma_copies, rng_calls;
#define PLIC_CLAIM_COMPLETE (&claim)
static uint8_t random_pool[72];
static struct { uint8_t *data; } key = {random_pool};
static uint32_t AesKey[8], kHmacKey[8], aes_counter, aes_input[4];
typedef int mmio_region_t;
typedef int dif_hmac_t;
static void external_injection(void);
static bool inject_on_wait;
static mmio_region_t mmio_region_from_addr(uint32_t addr) { (void)addr; return 0; }
static uint32_t _aes_get_datainreg(uint32_t i) { return i * 4u; }
static bool mmio_region_get_bit32(mmio_region_t a, uint32_t b, uint32_t c) {
  (void)a; (void)b; (void)c; return true;
}
static void mmio_region_write32(mmio_region_t a, uint32_t reg, uint32_t value) {
  (void)a; aes_input[reg / 4u] = value;
}
static uint8_t stream(uint32_t offset) { return (uint8_t)(offset * 37u + (offset >> 3u) + 19u); }
static uint32_t mmio_region_read32(mmio_region_t a, uint32_t reg) {
  (void)a;
  uint32_t i = (reg - 16u) / 4u, mask = 0;
  for (uint32_t b = 0; b < 4; ++b) mask |= (uint32_t)stream(aes_counter * 16u + i * 4u + b) << (8u * b);
  uint32_t value = aes_input[i] ^ mask;
  if (i == 3) aes_counter++;
  return value;
}
static void aes_init(uint32_t *iv, uint32_t *aes_key) { (void)aes_key; aes_counter = iv[0]; }
static void add_u128_leword_visual(uint32_t *iv, uint32_t blocks) { iv[0] += blocks; }
static uint8_t *dma_byte(uint32_t addr) {
  if (addr >= TCDM_BASE && addr < TCDM_BASE + 16u)
    return (uint8_t *)(uintptr_t)(TCDM_BASE + ((addr - TCDM_BASE) / 4u) * 16u + (addr % 4u));
  return (uint8_t *)(uintptr_t)addr;
}
static int idma_issue_1d(uint32_t src, uint32_t dst, uint32_t n) {
  for (uint32_t i = 0; i < n; ++i) *dma_byte(dst + i) = *dma_byte(src + i);
  dma_copies++;
  return 1;
}
static void wait_for_idma_eot(int ticket) {
  (void)ticket;
  if (inject_on_wait) { inject_on_wait = false; external_injection(); }
}
static void mailbox_read(unsigned box, uint32_t *a, uint32_t *b) { assert(box == 1); *a = mb_letter0; *b = mb_flags; }
static void mailbox_send(unsigned box, uint32_t a, uint32_t b) { (void)box; (void)a; (void)b; }
static void mb_write(uint32_t value, uint32_t reg) { (void)value; if (reg == MBOX_CAR_INT_SND_CLR(1)) acks++; }
static uintptr_t eu_evt_trig_cluster_addr(unsigned event) { (void)event; return (uintptr_t)&eu_event; }
static void pulp_cluster_kick_off(void *addr) { (void)addr; }
static void initialize_memory(void) { memset(random_pool, 0, sizeof(random_pool)); }
static void utils_csrng_randgen(void *pool, uint32_t words) {
  (void)pool; (void)words; rng_calls++; memset(random_pool, 0, sizeof(random_pool));
  ((uint32_t *)random_pool)[0] = rng_calls * 100;
}
static int hmac_result = 1;
static void test_setup(mmio_region_t addr, dif_hmac_t *hmac) { (void)addr; *hmac = 0; }
static int run_test(const dif_hmac_t *hmac, const char *data, size_t len, const uint8_t *k, uint32_t *digest) {
  (void)hmac; (void)data; (void)len; (void)k; (void)digest; return hmac_result;
}
static struct { uint32_t base, iv[4], key[8]; } metadata[16];
static void hashmap_init(void) { memset(metadata, 0, sizeof(metadata)); }
static int hashmap_push_random(uint32_t k, uint32_t value, uint32_t *iv, uint32_t *aes_key) {
  assert(k == value);
  for (unsigned i = 0; i < 16; ++i) if (metadata[i].base == k || metadata[i].base == 0) {
    metadata[i].base = k; memcpy(metadata[i].iv, iv, 16); memcpy(metadata[i].key, aes_key, 32); return 0;
  }
  return HM_ERR_FULL;
}
static int hashmap_get_random(uint32_t k, uint32_t *value, uint32_t *iv, uint32_t *aes_key) {
  for (unsigned i = 0; i < 16; ++i) if (metadata[i].base == k) {
    *value = k; memcpy(iv, metadata[i].iv, 16); memcpy(aes_key, metadata[i].key, 32); return HM_TRUE;
  }
  return 0;
}
#include "../deeploy_ot_service.inc"

#define DESC_ADDR 0x78000000u
#define SRC_ADDR 0x78001000u
#define DST_ADDR 0x78002000u
#define OUT_ADDR 0x78003000u
#define DONE_ADDR 0x78004000u
static deeploy_ot_task_t *descriptor = (deeploy_ot_task_t *)(uintptr_t)DESC_ADDR;
static void test_send(uint32_t flags) {
  mb_letter0 = DESC_ADDR; mb_flags = flags; claim = OT_MAILBOX_IRQ; external_irq_handler();
}
static void pump(void) {
  ot_request_t request;
  assert(ot_queue_pop(&ot_queue, &request));
  if (ot_deferred) { ot_accept(ot_deferred_letter0, ot_deferred_flags); ot_deferred = false; }
  ot_execute(&request);
}
static void plain_request(uint32_t ticket) {
  *descriptor = (deeploy_ot_task_t){.src = (void *)(uintptr_t)SRC_ADDR, .dst = (void *)(uintptr_t)DST_ADDR,
    .size = 17, .completion_addr = DONE_ADDR, .completion_value = ticket};
}
static void external_injection(void) { plain_request(99); test_send(0); }
static void test_mailbox(void) {
  memset((void *)(uintptr_t)SRC_ADDR, 0x5A, 128);
  plain_request(1); test_send(0);
  assert(acks == 1 && dma_copies == 0 && *(uint32_t *)(uintptr_t)DONE_ADDR == 0);
  descriptor->size = 999; // sender reused descriptor immediately after ACK
  inject_on_wait = true;
  pump(); // receives another request while worker waits for iDMA
  assert(*(uint32_t *)(uintptr_t)DONE_ADDR == 1 && eu_event == 0);
  assert(memcmp((void *)(uintptr_t)SRC_ADDR, (void *)(uintptr_t)DST_ADDR, 17) == 0);
  pump(); assert(*(uint32_t *)(uintptr_t)DONE_ADDR == 99);
  for (unsigned i = 0; i < OT_QUEUE_DEPTH; ++i) { plain_request(i + 2); test_send(0); }
  uint32_t previous_acks = acks;
  plain_request(42); test_send(0);
  assert(ot_deferred && acks == previous_acks);
  pump(); // admits deferred request before executing old head
  assert(!ot_deferred && acks == previous_acks + 1);
  descriptor->size = 999;
  for (unsigned i = 0; i < OT_QUEUE_DEPTH; ++i) pump();
  assert(*(uint32_t *)(uintptr_t)DONE_ADDR == 42 && eu_event == 0);
  plain_request(0); descriptor->completion_addr = 0; test_send(0); pump();
  assert(eu_event == 1); eu_event = 0;
  mb_letter0 = 0; mb_flags = INIT_MASK; claim = OT_MAILBOX_IRQ;
  external_irq_handler(); pump(); assert(eu_event == 1); eu_event = 0;
}
static void test_secure_tiles(void) {
  uint8_t *source = (uint8_t *)(uintptr_t)SRC_ADDR;
  uint8_t *output = (uint8_t *)(uintptr_t)OUT_ADDR;
  for (unsigned i = 0; i < 128; ++i) source[i] = (uint8_t)i;
  memset((void *)(uintptr_t)DST_ADDR, 0xA5, 128);
  // Two producer tiles, 3 rows of 7 and 10 bytes. External stride is 17.
  for (unsigned tile = 0; tile < 2; ++tile) {
    *descriptor = (deeploy_ot_task_t){.src = (void *)(uintptr_t)(SRC_ADDR + (tile ? 7 : 0)),
      .dst = (void *)(uintptr_t)(DST_ADDR + (tile ? 7 : 0)), .size = 3 * (tile ? 10 : 7),
      .size_1d = tile ? 10 : 7, .repetitions = 3, .src_stride = 17, .dst_stride = 17,
      .src_key = DST_ADDR, .dst_key = DST_ADDR, .completion_addr = DONE_ADDR, .completion_value = tile + 1};
    test_send(GEOMETRY_MASK | SECURE_MASK); pump();
  }
  // Consumer requests a different tiling: one 51-byte region, then a slice
  // beginning halfway through an AES block. Both must recover the same bytes.
  memset(output, 0xA5, 128);
  *descriptor = (deeploy_ot_task_t){.src = (void *)(uintptr_t)DST_ADDR, .dst = (void *)(uintptr_t)OUT_ADDR,
    .size = 51, .src_key = DST_ADDR, .dst_key = DST_ADDR, .completion_addr = DONE_ADDR, .completion_value = 3};
  test_send(SECURE_MASK | OPERATION_MASK); pump();
  assert(memcmp(source, output, 51) == 0 && output[51] == 0xA5);
  descriptor->src = (void *)(uintptr_t)(DST_ADDR + 5); descriptor->size = 37;
  memset(output, 0xA5, 128); test_send(SECURE_MASK | OPERATION_MASK); pump();
  assert(memcmp(source + 5, output, 37) == 0 && output[37] == 0xA5);
  assert(((uint8_t *)(uintptr_t)DST_ADDR)[51] == 0xA5);
  assert(eu_event == 0);
}
static void test_degenerate_2d_and_errors(void) {
  uint8_t *source = (uint8_t *)(uintptr_t)SRC_ADDR;
  uint8_t *output = (uint8_t *)(uintptr_t)OUT_ADDR;
  // Same region as the previous test, but a 2D descriptor with repetitions=1.
  *descriptor = (deeploy_ot_task_t){.src = (void *)(uintptr_t)(DST_ADDR + 9),
    .dst = (void *)(uintptr_t)OUT_ADDR, .size = 13, .size_1d = 13, .repetitions = 1,
    .src_stride = 17, .dst_stride = 13, .src_key = DST_ADDR, .dst_key = DST_ADDR,
    .completion_addr = DONE_ADDR, .completion_value = 100};
  memset(output, 0xA5, 128);
  test_send(GEOMETRY_MASK | SECURE_MASK | OPERATION_MASK); pump();
  assert(memcmp(source + 9, output, 13) == 0 && output[13] == 0xA5);
  assert(*(uint32_t *)(uintptr_t)DONE_ADDR == 100);
  // Starting another complete output at its base must renew metadata.
  uint32_t previous_rng = rng_calls;
  descriptor->src = (void *)(uintptr_t)SRC_ADDR;
  descriptor->dst = (void *)(uintptr_t)DST_ADDR;
  test_send(GEOMETRY_MASK | SECURE_MASK); pump();
  assert(rng_calls == previous_rng + 1);

  // Failed HMAC must never produce an EU or successful data completion.
  hmac_result = -1; eu_event = 0;
  expect_fatal = true;
  if (setjmp(fatal_jump) == 0) { test_send(HMAC_MASK); pump(); assert(false); }
  expect_fatal = false; hmac_result = 1;
  assert(eu_event == 0 && *(uint32_t *)(uintptr_t)DONE_ADDR == 100);

  // Malformed geometry must be rejected before doing DMA or completing.
  descriptor->size = 14;
  uint32_t previous_dma = dma_copies;
  expect_fatal = true;
  if (setjmp(fatal_jump) == 0) { test_send(GEOMETRY_MASK); pump(); assert(false); }
  expect_fatal = false;
  assert(dma_copies == previous_dma && eu_event == 0);
}
int main(void) {
#ifdef _WIN32
  void *memory = VirtualAlloc((void *)(uintptr_t)DESC_ADDR, 0x20000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#else
  void *memory = mmap((void *)(uintptr_t)DESC_ADDR, 0x20000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
#endif
  assert(memory == (void *)(uintptr_t)DESC_ADDR);
  test_mailbox(); test_secure_tiles(); test_degenerate_2d_and_errors();
  puts("PASS: actual service admission/backpressure/reentrant IRQ/completions/2D crypto byte ranges");
  return 0;
}
