// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

#include "sw/device/lib/testing/test_framework/ottf_main.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/dif/dif_uart.h"

#include "sw/device/lib/dif/dif_hmac.h"
#include "sw/device/lib/testing/hmac_testutils.h"


#include "sw/device/silicon_creator/rom/uart.h"
#include "sw/device/silicon_creator/rom/string_lib.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/base/abs_mmio.h"

//import from AES test
#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/memory.h"



//generated with regtool.py
#include "aes_regs.h"


#include "mbox.h"

#include "idma.h"
#include "cluster.h"
#include "utils.h"
#include "hashmap.h"

#include "edn_regs.h"
#include "csrng_regs.h"  // Generated
#include "entropy_src_regs.h"  // Generated.
#define TITANSSL_IBL1_BASE 0xe0004000
#define TITANSSL_TEST_WORDSIZES  18

typedef struct {
    uint8_t *data;
} titanssl_batch_t;

static void ot_worker_run(void);

static titanssl_batch_t key;

#define ENTROPY_CMD(m, i) ((bitfield_field32_t){.mask = m, .index = i})

void initialize_memory() {

  key.data = (uint8_t*) TITANSSL_IBL1_BASE;
  for(size_t i=0; i<TITANSSL_TEST_WORDSIZES*4; i++)
    key.data[i] = 0x00;
}

void print_results(uint32_t words) {

  for(size_t i=0; i<words; i++)
    printf("DATA %d: 0x%x\r\n", i, ((uint32_t*)key.data)[i]);
}


//#include "qyolo_pulp_cluster_runtime_payload.h"

//comment this to disable cycle counters OT side
//#define OT_BENCHMARK

#define N_BYTES 4096
#define N_WORDS (N_BYTES/4)



enum operation_enum {ENCRYPTION,DECRYPTION};
enum offset_enum {SRC_BASED,DST_BASED};
void pulp_cluster_kick_off(void* boot_addr);

//### AES CTR ###

static  uint32_t AesKey[8] = {
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0
};

static  uint32_t AesIv[4] = {
    0x00000000, 0x00000000,
    0x00000000, 0x00000000
};

//AES utils

uint32_t _aes_get_keyreg(uint32_t idx){
    uint32_t reg_offset[8*2] = {
        AES_KEY_SHARE0_0_REG_OFFSET,
        AES_KEY_SHARE0_1_REG_OFFSET,
        AES_KEY_SHARE0_2_REG_OFFSET,
        AES_KEY_SHARE0_3_REG_OFFSET,
        AES_KEY_SHARE0_4_REG_OFFSET,
        AES_KEY_SHARE0_5_REG_OFFSET,
        AES_KEY_SHARE0_6_REG_OFFSET,
        AES_KEY_SHARE0_7_REG_OFFSET,
        AES_KEY_SHARE1_0_REG_OFFSET,
        AES_KEY_SHARE1_1_REG_OFFSET,
        AES_KEY_SHARE1_2_REG_OFFSET,
        AES_KEY_SHARE1_3_REG_OFFSET,
        AES_KEY_SHARE1_4_REG_OFFSET,
        AES_KEY_SHARE1_5_REG_OFFSET,
        AES_KEY_SHARE1_6_REG_OFFSET,
        AES_KEY_SHARE1_7_REG_OFFSET
    };
    return reg_offset[idx];
}

uint32_t _aes_get_ivreg(uint32_t idx){
    uint32_t reg_offset[4] = {
        AES_IV_0_REG_OFFSET,
        AES_IV_1_REG_OFFSET,
        AES_IV_2_REG_OFFSET,
        AES_IV_3_REG_OFFSET
    };
    return reg_offset[idx];
}

uint32_t _aes_get_datainreg(uint32_t idx){
    uint32_t reg_offset[4] = {
        AES_DATA_IN_0_REG_OFFSET,
        AES_DATA_IN_1_REG_OFFSET,
        AES_DATA_IN_2_REG_OFFSET,
        AES_DATA_IN_3_REG_OFFSET
    };
    return reg_offset[idx];
}




void aes_init(uint32_t* aes_iv, uint32_t *aes_key) {

  mmio_region_t aes;
  uint32_t reg;

  uint32_t* tcdm = (uint32_t*) TCDM_BASE;

  //printf_init();
  utils_entropy_init();

  int next = 0;

  //printf("[OpenTitan🐯] AES Setup START\r\n");

  aes = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR);

  // Reset the IP
  while(!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT)); //ATTENDE CHE L'ACCELERATORE AES SIA IDLE
  reg = bitfield_bit32_write(0, \
    AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT, true);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);
  reg = bitfield_bit32_write(0, \
    AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT, true);
  reg = bitfield_bit32_write(reg, \
    AES_TRIGGER_DATA_OUT_CLEAR_BIT, true);
  mmio_region_write32(aes, \
    AES_TRIGGER_REG_OFFSET, reg);
  while (!mmio_region_get_bit32(aes, \
    AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  reg = bitfield_field32_write(0, \
    AES_CTRL_SHADOWED_OPERATION_FIELD, \
    AES_CTRL_SHADOWED_OPERATION_MASK);
  reg = bitfield_field32_write(reg, \
    AES_CTRL_SHADOWED_MODE_FIELD, \
    AES_CTRL_SHADOWED_MODE_VALUE_AES_NONE);
  reg = bitfield_field32_write(reg, \
    AES_CTRL_SHADOWED_KEY_LEN_FIELD, \
    AES_CTRL_SHADOWED_KEY_LEN_MASK);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);

    // Initialize AES IP configurations
  while(!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  reg = bitfield_field32_write(0, \
      AES_CTRL_SHADOWED_OPERATION_FIELD, \
      AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC);
  reg = bitfield_field32_write(reg, \
    AES_CTRL_SHADOWED_MODE_FIELD, \
    AES_CTRL_SHADOWED_MODE_VALUE_AES_CTR); //CBC al posto di CTR
  reg = bitfield_field32_write(reg, \
    AES_CTRL_SHADOWED_KEY_LEN_FIELD, \
    AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256);
  reg = bitfield_field32_write(reg, \
    AES_CTRL_SHADOWED_PRNG_RESEED_RATE_FIELD, \
    AES_CTRL_SHADOWED_PRNG_RESEED_RATE_VALUE_PER_64);
  reg = bitfield_bit32_write(reg, \
    AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT, false);
  reg = bitfield_bit32_write(reg, \
    AES_CTRL_SHADOWED_SIDELOAD_BIT, false);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET, reg);

  // Initialize AES IP auxiliary configurations
  reg = bitfield_bit32_write(0, \
    AES_CTRL_AUX_SHADOWED_KEY_TOUCH_FORCES_RESEED_BIT, false);
  reg = bitfield_bit32_write(reg, \
    AES_CTRL_AUX_SHADOWED_FORCE_MASKS_BIT, false);
  mmio_region_write32(aes, \
    AES_CTRL_AUX_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, \
    AES_CTRL_AUX_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, \
    AES_CTRL_AUX_REGWEN_REG_OFFSET, true);


  // Initialize key shares correctly
  for (size_t i = 0; i < 8; i++) {
    mmio_region_write32(aes,
        _aes_get_keyreg(i),
        aes_key[i]);          // SHARE0 = FF
    mmio_region_write32(aes,
        _aes_get_keyreg(i + 8),
        0x00000000);         // SHARE1 = 0
  }

  reg = mmio_region_read32(aes, \
    AES_CTRL_SHADOWED_REG_OFFSET);
  reg = bitfield_field32_read(reg, AES_CTRL_SHADOWED_MODE_FIELD);
  if (reg != AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB) {
      while(!mmio_region_get_bit32(aes, \
        AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
      for (size_t i=0; i<4; i++) {
          mmio_region_write32(aes, \
            _aes_get_ivreg(i), \
            aes_iv[i]);         //IV Parametro della funzione
      }
  }


}

uint32_t  AesTestIv[4] = {
          0x00000000, 0x00000000,
          0x00000000, 0xCACACACA
        };

uint32_t  AesTestKey[8] = {
  0x00000000, 0x00000000,
  0x00000000, 0xCACACACA,
  0x00000000, 0x00000000,
  0x00000000, 0xCACACACA,
};

void utils_csrng_randgen(titanssl_batch_t *dat, uint32_t words) {

  mmio_region_t entropy_src, csrng, edn0, edn1;
  uint32_t reg, len;
  bool ready;

  static const bitfield_field32_t kAppCmdFieldFlag0 = ENTROPY_CMD(0xf, 8);
  static const bitfield_field32_t kAppCmdFieldCmdId = ENTROPY_CMD(0xf, 0);
  static const bitfield_field32_t kAppCmdFieldCmdLen = ENTROPY_CMD(0xf, 4);
  static const bitfield_field32_t kAppCmdFieldGlen = ENTROPY_CMD(0x7ffff, 12);

  entropy_src = mmio_region_from_addr(TOP_EARLGREY_ENTROPY_SRC_BASE_ADDR);
  csrng = mmio_region_from_addr(TOP_EARLGREY_CSRNG_BASE_ADDR);
  edn0 = mmio_region_from_addr(TOP_EARLGREY_EDN0_BASE_ADDR);
  edn1 = mmio_region_from_addr(TOP_EARLGREY_EDN1_BASE_ADDR);

    // reset edn0
  reg = mmio_region_read32(edn0, EDN_CTRL_REG_OFFSET);
  reg = bitfield_field32_write(reg, EDN_CTRL_CMD_FIFO_RST_FIELD,
                               kMultiBitBool4True);
  mmio_region_write32(edn0, EDN_CTRL_REG_OFFSET, reg);
  mmio_region_write32(edn0, EDN_CTRL_REG_OFFSET, EDN_CTRL_REG_RESVAL);

    // reset edn1
  reg = mmio_region_read32(edn1, EDN_CTRL_REG_OFFSET);
  reg = bitfield_field32_write(reg, EDN_CTRL_CMD_FIFO_RST_FIELD,
                               kMultiBitBool4True);
  mmio_region_write32(edn1, EDN_CTRL_REG_OFFSET, reg);
  mmio_region_write32(edn1, EDN_CTRL_REG_OFFSET, EDN_CTRL_REG_RESVAL);

    // reset csrng
  mmio_region_write32(csrng, CSRNG_CTRL_REG_OFFSET, CSRNG_CTRL_REG_RESVAL);

    // reset entropy
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_MODULE_ENABLE_REG_OFFSET,
                      ENTROPY_SRC_MODULE_ENABLE_REG_RESVAL);
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_ENTROPY_CONTROL_REG_OFFSET,
                      ENTROPY_SRC_ENTROPY_CONTROL_REG_RESVAL);

  mmio_region_write32(entropy_src, ENTROPY_SRC_CONF_REG_OFFSET,
                      ENTROPY_SRC_CONF_REG_RESVAL);

  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_OFFSET,
                      ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_RESVAL);

  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_ALERT_THRESHOLD_REG_OFFSET,
                      ENTROPY_SRC_ALERT_THRESHOLD_REG_RESVAL);

    // entropy configure
  reg = bitfield_field32_write(
      0, ENTROPY_SRC_ENTROPY_CONTROL_ES_ROUTE_FIELD,
      kMultiBitBool4False);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_ENTROPY_CONTROL_ES_TYPE_FIELD,
      kMultiBitBool4False);
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_ENTROPY_CONTROL_REG_OFFSET, reg);
  reg = bitfield_field32_write(
      0, ENTROPY_SRC_CONF_FIPS_ENABLE_FIELD,
      kMultiBitBool4True);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_CONF_ENTROPY_DATA_REG_ENABLE_FIELD,
      kMultiBitBool4False);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_CONF_THRESHOLD_SCOPE_FIELD,
      kMultiBitBool4True);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_CONF_RNG_BIT_ENABLE_FIELD, kMultiBitBool4False);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_CONF_RNG_BIT_SEL_FIELD, 4);
  reg = bitfield_field32_write(
      reg, ENTROPY_SRC_CONF_ENTROPY_DATA_REG_ENABLE_FIELD,
      kMultiBitBool4False);
  mmio_region_write32(entropy_src, ENTROPY_SRC_CONF_REG_OFFSET,
                      reg);
  reg = bitfield_field32_write(ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_RESVAL,
                             ENTROPY_SRC_HEALTH_TEST_WINDOWS_FIPS_WINDOW_FIELD,
                             0x0200);
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_OFFSET,
                      reg);

  reg = bitfield_field32_write(
      0, ENTROPY_SRC_ALERT_THRESHOLD_ALERT_THRESHOLD_FIELD,
      2);
  reg = bitfield_field32_write(
      2, ENTROPY_SRC_ALERT_THRESHOLD_ALERT_THRESHOLD_INV_FIELD,
      0xFFFD);
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_ALERT_THRESHOLD_REG_OFFSET, reg);
  mmio_region_write32(entropy_src,
                      ENTROPY_SRC_MODULE_ENABLE_REG_OFFSET,
                      kMultiBitBool4True);

    // configure csrng
  reg =
      bitfield_field32_write(0, CSRNG_CTRL_ENABLE_FIELD, kMultiBitBool4True);
  reg = bitfield_field32_write(reg, CSRNG_CTRL_SW_APP_ENABLE_FIELD,
                               kMultiBitBool4True);
  reg = bitfield_field32_write(reg, CSRNG_CTRL_READ_INT_STATE_FIELD,
                               kMultiBitBool4True);
  mmio_region_write32(csrng, CSRNG_CTRL_REG_OFFSET, reg);

  // entropy reseed
  ready = false;
  do {
    reg = abs_mmio_read32(TOP_EARLGREY_CSRNG_BASE_ADDR + CSRNG_SW_CMD_STS_REG_OFFSET);
    ready = bitfield_bit32_read(reg, CSRNG_SW_CMD_STS_CMD_RDY_BIT);
  } while (!ready);

  reg = bitfield_field32_write(0, kAppCmdFieldCmdId, 2);
  reg = bitfield_field32_write(reg, kAppCmdFieldCmdLen, 0);
  reg = bitfield_field32_write(reg, kAppCmdFieldGlen, 0);

  abs_mmio_write32(TOP_EARLGREY_CSRNG_BASE_ADDR + CSRNG_CMD_REQ_REG_OFFSET, reg);
  
  // csrng generate
  ready = false;
  do {
    reg = mmio_region_read32(csrng, CSRNG_SW_CMD_STS_REG_OFFSET);
    ready = bitfield_bit32_read(reg, CSRNG_SW_CMD_STS_CMD_RDY_BIT);
  } while (!ready);

  len = (words + 3) / 4;

  reg = bitfield_field32_write(0, kAppCmdFieldCmdId, 3);
  reg = bitfield_field32_write(reg, kAppCmdFieldCmdLen, 0);
  reg = bitfield_field32_write(
      reg, kAppCmdFieldFlag0, kMultiBitBool4False); // kMultiBitBool4True or kMultiBitBool4False ?
  reg = bitfield_field32_write(reg, kAppCmdFieldGlen, len);

  mmio_region_write32(csrng, CSRNG_CMD_REQ_REG_OFFSET, reg);

  do {
    reg = mmio_region_read32(csrng, CSRNG_GENBITS_VLD_REG_OFFSET);
    ready = bitfield_bit32_read(reg, CSRNG_GENBITS_VLD_GENBITS_VLD_BIT);
  } while (!ready);

  for (size_t i = 0; i < words; ++i) {
    if (i % 4 == 0) {
      do {
        reg = mmio_region_read32(csrng, CSRNG_GENBITS_VLD_REG_OFFSET);
        ready = bitfield_bit32_read(reg, CSRNG_GENBITS_VLD_GENBITS_VLD_BIT);
      } while (!ready);
    }
    ((uint32_t*)dat->data)[i] = mmio_region_read32(csrng, CSRNG_GENBITS_REG_OFFSET);
  }

}



int main(int argc, char **argv) {



  //WARNING: rom/silicon_creator/uart.h has been modified to support astral architecture

  astral_uart_init(50000000, 115200);

  hashmap_init();


  //uint32_t start_cycles = ibex_mcycle_read();
  //printf("[OT] Cycles: %d\r\n", end_cycles-start_cycles);

  //-----------PLIC------------------------- =>>>>> TODO: fare subroutine
  printf("OpenTitan🐯: PLIC set UP...\r\n");

  int volatile * plic_prio, * plic_en;
  int volatile * p_reg;
  uint32_t volatile a = 0;
  uint32_t volatile b = 0;
  
 
  unsigned val = 0xe0000001;        
  asm volatile("csrw mtvec, %0\n" : : "r"(val)); // move irq vector to SRAM base address
   
  unsigned val_1 = 0x00001808;      // Set global interrupt enable in ibex regs
  unsigned val_2 = 0x00000800;      // Set external interrupts

  asm volatile("csrw  mstatus, %0\n" : : "r"(val_1)); 
  asm volatile("csrw  mie, %0\n"     : : "r"(val_2));

  plic_prio  = (int *) 0xC800027C;  // Priority reg
  plic_en    = (int *) 0xC8002010;  // Enable reg

  *plic_prio  = 1;                   // Set mbox interrupt priority to 1
  *plic_en    = 0x80000000;          // Enable interrupt
  //-----------PLIC-------------------------

  //TODO: CSRNG_test
  printf("MEMORY INIT\r\n");    
  initialize_memory();
  printf("TEST START\r\n");
  utils_csrng_randgen(&key, TITANSSL_TEST_WORDSIZES);
  printf("RESULTS\r\n");
  print_results(TITANSSL_TEST_WORDSIZES);
  printf("DONE\r\n");


  ot_worker_run();


  return 0; 
}

static volatile int8_t *pointer = 0;

static uint32_t kHmacKey[8] = {
    0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0,
};

static const dif_hmac_transaction_t kHmacTransactionConfig = {
    .digest_endianness = kDifHmacEndiannessLittle,
    .message_endianness = kDifHmacEndiannessLittle,
    // .digest_endianness = kDifHmacEndiannessBig,
    // .message_endianness = kDifHmacEndiannessBig,
};

/**
 * Initialize the HMAC engine. Return `true` if the configuration is valid.
 */
static void test_setup(mmio_region_t base_addr, dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_init(base_addr, hmac));
}

/**
 * Start HMAC in the correct mode. If `key` == NULL use SHA256 mode, otherwise
 * use the provided key in HMAC mode.
 */
static void test_start(const dif_hmac_t *hmac, const uint8_t *key) {
  // Let a null key indicate we are operating in SHA256-only mode.
  if (key == NULL) {
    CHECK_DIF_OK(dif_hmac_mode_sha256_start(hmac, kHmacTransactionConfig));
  } else {
    CHECK_DIF_OK(dif_hmac_mode_hmac_start(hmac, key, kHmacTransactionConfig));
  }
}

/**
 * Kick off the HMAC (or SHA256) run.
 */
static void run_hmac(const dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_process(hmac));
}

static int run_test(const dif_hmac_t *hmac, const char *data, size_t len,
                     const uint8_t *key,
                     uint32_t *expected_digest) {

  dif_hmac_digest_t digest;

  test_start(hmac, key);
  hmac_testutils_push_message(hmac, data, len);
  hmac_testutils_fifo_empty_polled(hmac);
  hmac_testutils_check_message_length(hmac, len * 8);
  run_hmac(hmac);
  
  //attende il risultato e lo salva in digest.digest
  hmac_testutils_finish_polled(hmac, &digest);
  int j = 0;
  for(int i = 7; i >= 0; i--){
    //printf("digest[%d] = %x\r\n", i, swap_endianness((uint32_t) digest.digest[i]));
    if(swap_endianness((uint32_t) digest.digest[i]) != expected_digest[j++]){
      return -1;
    }
  }

  return 1;

}


#include "deeploy_ot_service.inc"

static inline void writew(uint32_t val, uintptr_t addr)
{
	asm volatile("sw %0, 0(%1)"
		     :
		     : "r"(val), "r"((volatile uint32_t *)addr)
		     : "memory");
}

void pulp_cluster_kick_off(void* boot_addr){

    volatile uint32_t cluster_boot_reg_addr = 0x50200040;

    for (int i = 0; i < 8; i++) {
      writew((uint32_t) boot_addr, cluster_boot_reg_addr);
      cluster_boot_reg_addr += 0x4;
    }

    //pulp_cluster_start
    writew(1, INT_CLUSTER_BOOTEN_ADDR);
    writew(1, INT_CLUSTER_FETCHEN_ADDR);

}






