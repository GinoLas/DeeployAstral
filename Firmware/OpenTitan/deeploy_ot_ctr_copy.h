// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
#ifndef DEEPLOY_OT_CTR_COPY_H_
#define DEEPLOY_OT_CTR_COPY_H_
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// The AES engine must already be initialized to IV + floor(offset / 16).
// All callbacks are synchronous; read/write touch EXACTLY n bytes.
// Keeping this algorithm hardware-independent permits host boundary tests.
typedef struct {
  void (*read)(void *ctx, uint32_t src, uint8_t *out, uint32_t n);
  void (*write)(void *ctx, uint32_t dst, const uint8_t *in, uint32_t n);
  void (*aes_block)(void *ctx, const uint8_t in[16], uint8_t out[16]);
  void *ctx;
} ot_ctr_io_t;

static inline void ot_ctr_copy(const ot_ctr_io_t *io, uint32_t src, uint32_t dst,
                               uint32_t size, uint32_t offset) {
  uint32_t skip = offset % 16u;
  while (size != 0) {
    uint8_t input[16] = {0}, output[16];
    uint32_t n = 16u - skip;
    if (n > size) n = size;
    io->read(io->ctx, src, input + skip, n);
    io->aes_block(io->ctx, input, output);
    io->write(io->ctx, dst, output + skip, n);
    src += n;
    dst += n;
    size -= n;
    skip = 0;
  }
}
#endif
