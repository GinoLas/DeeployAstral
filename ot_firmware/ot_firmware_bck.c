// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Firmware OpenTitan per il trasferimento sicuro (AES-CTR) tra L2 e cluster PULP.
//
// Idea di fondo
//   * Attivazioni: UNA sola chiave e UN solo IV per tutte, generati una volta all'avvio di
//     OpenTitan (non durante la rete). Il contatore CTR dipende solo dall'indirizzo L2:
//         blocco = (indirizzo_L2 - L2_ARENA_BASE) / 16
//     Chi scrive e chi legge lo stesso byte arrivano allo stesso blocco, qualunque sia il
//     loro tiling. Niente tabelle, niente transfer_id, niente accordi tra produttore e consumatore.
//   * Pesi: IV e chiave vengono annunciati dal cluster (IV_MASK / INIT_MASK) e il contatore e'
//     relativo alla base del tensore (come nel firmware originale).
//   * Ogni segmento (una riga di un trasferimento 2D) e' un trasferimento a se': si copia il dato
//     in una finestra di blocchi interi in TCDM all'offset `head`, si cifra/decifra la finestra,
//     e si copia fuori solo il segmento utile. I byte attorno al segmento sono spazzatura e
//     vengono scartati (in CTR ogni byte dipende solo dal suo keystream, non dai vicini).
//
// Limite noto: con un solo IV e una sola chiave, lo stesso indirizzo L2 ha sempre lo stesso keystream,
// anche per tensori diversi e per inferenze diverse.

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

#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/mmio.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/memory.h"

#include "aes_regs.h"   // generato con regtool.py

#include "mbox.h"
#include "idma.h"
#include "cluster.h"
#include "utils.h"
#include "hashmap.h"

#include "edn_regs.h"
#include "csrng_regs.h"          // Generated
#include "entropy_src_regs.h"    // Generated

// =====================================================================
// Configurazione
// =====================================================================

#define L2_ARENA_BASE          0x78000000u   // inizio della L2: origine del contatore delle attivazioni
#define CLUSTER_ADDR_LIMIT     0x50000000u   // sotto questo valore gli indirizzi sono relativi al cluster
#define MAILBOX_IRQ_ID         159

#define TITANSSL_IBL1_BASE     0xe0004000    // scratch per l'entropia, in SRAM OT
#define TITANSSL_TEST_WORDSIZES 18
#define ACT_RANDOM_WORDS       12            // 4 parole di IV + 8 parole di chiave (una volta, all'avvio)

// 1 = tra due segmenti con la stessa chiave si riscrive solo l'IV (veloce, da verificare sul SoC
//     con aes_fast_iv_test.c); 0 = aes_init completo a ogni segmento (lento, sicuro).
#define AES_FAST_IV            1

// 1 = misura i cicli (mcycle) per funzione e stampa un riepilogo alla fine della rete.
//     Ogni misura costa qualche decina di cicli: il riepilogo riporta l'overhead stimato.
#define OT_PROFILE             0

#define OT_DEBUG 0                           // 1 = stampe di debug
#define DBG(...) do { if (OT_DEBUG) printf(__VA_ARGS__); } while (0)

//comment this to disable cycle counters OT side
//#define OT_BENCHMARK

#define ENTROPY_CMD(m, i) ((bitfield_field32_t){.mask = m, .index = i})

typedef struct {
    uint8_t *data;
} titanssl_batch_t;

static titanssl_batch_t rng;                 // buffer dell'entropia (punta a TITANSSL_IBL1_BASE)

static uint32_t AesKey[8]   = {0};           // chiave dei pesi, ricevuta con INIT_MASK
static uint32_t kHmacKey[8] = {0};

static void fatal(const char *msg) {
  printf("[OT] FATAL: %s\r\n", msg);
  while (1) {
    asm volatile("wfi");
  }
}

static void rng_buffer_init(void) {
  rng.data = (uint8_t*) TITANSSL_IBL1_BASE;
  for (size_t i = 0; i < TITANSSL_TEST_WORDSIZES * 4; i++)
    rng.data[i] = 0x00;
}

// =====================================================================
// SEZIONE P - Profilo dei cicli OT (mcycle), per funzione
// =====================================================================
//
// Ogni funzione misurata ha un contatore globale. Si attribuisce il tempo con una pila di frame:
//   self = cicli spesi nella funzione stessa (escluse le funzioni misurate che chiama)
//   incl = cicli dall'ingresso all'uscita (comprese le funzioni che chiama)
// Il tempo in cui non c'e' nessun frame attivo (main, wfi) va in PROF_OUTSIDE.
// Con OT_PROFILE = 0 tutte le macro spariscono e non resta nessun costo.

#if OT_PROFILE

static bool prof_report_pending = false;   // il riepilogo si stampa a fine handler, non dentro

typedef enum {
  PROF_OUTSIDE = 0,     // nessuna funzione misurata attiva (main, idle)
  PROF_IRQ,             // irq handler, totale
  PROF_MAILBOX,         // clear degli interrupt + lettura della mailbox
  PROF_MSG_HOST,        // avvio del cluster
  PROF_MSG_END,         // fine rete
  PROF_MSG_INIT,        // INIT_MASK
  PROF_MSG_HMAC,        // HMAC dei pesi
  PROF_MSG_IV,          // annuncio IV dei pesi
  PROF_PLAIN,           // trasferimento non sicuro
  PROF_SECURE,          // trasferimento sicuro (intero, tutte le righe)
  PROF_WEIGHTS_CTX,     // hashmap per i pesi
  PROF_CRYPT_SEGMENT,   // un segmento (una riga)
  PROF_ADD_IV,          // add_u128_leword_visual
  PROF_AES_START,       // aes_start (scelta tra init completo e solo IV)
  PROF_AES_INIT,        // aes_init completo
  PROF_ENTROPY_INIT,    // utils_entropy_init, dentro aes_init
  PROF_AES_SET_IV,      // solo riscrittura IV
  PROF_DMA_IN,          // DMA dentro la finestra
  PROF_DMA_OUT,         // DMA fuori dalla finestra
  PROF_DMA_ISSUE,       // idma_issue_1d
  PROF_DMA_WAIT,        // wait_for_idma_eot
  PROF_AES_LOOP,        // ciclo AES sui blocchi
  PROF_AES_WAIT,        // attesa di OUTPUT_VALID, dentro il ciclo AES
  PROF_NOTIFY,          // doorbell all'Event Unit del cluster
  PROF_CALIB,           // solo per misurare l'overhead
  PROF_COUNT
} prof_id_t;

static const char *const prof_names[PROF_COUNT] = {
  "fuori (main / idle)",
  "irq handler (totale)",
  "mailbox read/clear",
  "msg: avvio cluster",
  "msg: fine rete",
  "msg: INIT",
  "msg: HMAC",
  "msg: IV pesi",
  "plain_transfer",
  "secure_transfer",
  "weights_ctx (hashmap)",
  "crypt_segment (1 riga)",
  "add_u128 (contatore)",
  "aes_start",
  "aes_init completo",
  "utils_entropy_init",
  "aes_set_iv",
  "dma dentro la finestra",
  "dma fuori dalla finestra",
  "idma_issue_1d",
  "wait_for_idma_eot",
  "ciclo AES (blocchi)",
  "attesa OUTPUT_VALID",
  "notify cluster",
  "calibrazione",
};

#define PROF_MAX_DEPTH 24

typedef struct { prof_id_t id; uint32_t t_enter; } prof_frame_t;

static prof_frame_t prof_stack[PROF_MAX_DEPTH];
static int          prof_sp = 0;
static uint32_t     prof_last = 0;
static uint64_t     prof_self[PROF_COUNT], prof_incl[PROF_COUNT], prof_calls[PROF_COUNT];
static uint32_t     prof_pair_cycles = 0;     // costo misurato di una coppia enter/exit

static inline uint32_t prof_now(void) { return (uint32_t) ibex_mcycle_read(); }

// Attribuisce i cicli passati dall'ultimo evento alla funzione in cima alla pila.
static inline void prof_attribute(uint32_t now) {
  uint32_t delta = now - prof_last;       // corretto anche con un giro del contatore a 32 bit
  prof_last = now;
  prof_id_t who = (prof_sp > 0) ? prof_stack[prof_sp - 1].id : PROF_OUTSIDE;
  prof_self[who] += delta;
}

static inline void prof_enter(prof_id_t id) {
  uint32_t now = prof_now();
  prof_attribute(now);
  if (prof_sp < PROF_MAX_DEPTH) {
    prof_stack[prof_sp].id = id;
    prof_stack[prof_sp].t_enter = now;
    prof_sp++;
  }
}

static inline void prof_exit(prof_id_t id) {
  (void) id;
  uint32_t now = prof_now();
  prof_attribute(now);
  if (prof_sp > 0) {
    prof_sp--;
    prof_incl[prof_stack[prof_sp].id] += now - prof_stack[prof_sp].t_enter;
    prof_calls[prof_stack[prof_sp].id]++;
  }
}

// Azzera i contatori. I frame ancora aperti ripartono da adesso.
static void prof_reset(void) {
  uint32_t now = prof_now();
  memset(prof_self,  0, sizeof(prof_self));
  memset(prof_incl,  0, sizeof(prof_incl));
  memset(prof_calls, 0, sizeof(prof_calls));
  for (int i = 0; i < prof_sp; i++) prof_stack[i].t_enter = now;
  prof_last = now;
}

// Misura quanto costa una coppia enter/exit, poi azzera.
static void prof_init(void) {
  prof_sp = 0;
  prof_last = prof_now();
  uint32_t t0 = prof_now();
  for (int i = 0; i < 256; i++) {
    prof_enter(PROF_CALIB);
    prof_exit(PROF_CALIB);
  }
  uint32_t t1 = prof_now();
  prof_pair_cycles = (t1 - t0) >> 8;
  prof_reset();
}

// ---- aritmetica a 64 bit senza libgcc (niente moltiplicazioni/divisioni a 64 bit) ----

static uint32_t prof_div(uint64_t n, uint32_t d) {      // quoziente, saturato a 32 bit
  if (d == 0) return 0;
  uint64_t q = 0, r = 0;
  for (int i = 63; i >= 0; i--) {
    r = (r << 1) | ((n >> i) & 1u);
    if (r >= d) { r -= d; q |= (uint64_t) 1 << i; }
  }
  return q > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t) q;
}

static uint64_t prof_mul1000(uint64_t x) { return (x << 10) - (x << 4) - (x << 3); }

// percentuale con un decimale, in decimi (123 = 12.3)
static uint32_t prof_pct10(uint64_t part, uint64_t whole) {
  if (whole == 0) return 0;
  while (whole > 0xFFFFFFFFull) { whole >>= 1; part >>= 1; }   // porta `whole` in 32 bit
  return prof_div(prof_mul1000(part), (uint32_t) whole);
}

static void prof_print_num(uint32_t v, int width) {
  int digits = 1;
  for (uint32_t t = v; t >= 10; t /= 10) digits++;
  for (int i = digits; i < width; i++) printf(" ");
  printf("%d", (int) v);
}

static void prof_print_pct(uint32_t pct10, int width) {
  uint32_t whole = pct10 / 10;
  int digits = 1;
  for (uint32_t t = whole; t >= 10; t /= 10) digits++;
  for (int i = digits + 2; i < width; i++) printf(" ");
  printf("%d.%d", (int) whole, (int) (pct10 % 10));
}

// Stampa il nome e lo riempie di spazi fino a `width`, per allineare le colonne.
static void prof_print_name(const char *name, int width) {
  printf("%s", name);
  int n = 0;
  while (name[n] != '\0') n++;           // lunghezza a mano: strlen non e' disponibile
  for (int i = n; i < width; i++) printf(" ");
}

// Stampa il riepilogo, ordinato per tempo proprio decrescente. Percentuali sul totale dei cicli contati.
static void prof_report(void) {
  prof_attribute(prof_now());

  uint64_t total = 0, in_functions = 0, pairs = 0;
  for (int i = 0; i < PROF_COUNT; i++) {
    if (i == PROF_CALIB) continue;
    total += prof_self[i];
    if (i != PROF_OUTSIDE) { in_functions += prof_self[i]; pairs += prof_calls[i]; }
  }
  uint64_t overhead = (uint64_t) prof_pair_cycles * pairs;

  printf("\r\n[PROF] ===== profilo dei cicli di OpenTitan (da INIT a fine rete) =====\r\n");
  printf("[PROF] cicli contati: %d kc | dentro le funzioni: %d kc (", (int) prof_div(total, 1000), (int) prof_div(in_functions, 1000));
  prof_print_pct(prof_pct10(in_functions, total), 0);
  printf(" pct)\r\n");
  printf("[PROF] overhead stimato del profilatore: %d cicli per misura, %d misure, circa %d kc (", (int) prof_pair_cycles,
         (int) pairs, (int) prof_div(overhead, 1000));
  prof_print_pct(prof_pct10(overhead, total), 0);
  printf(" pct del totale)\r\n");
  printf("[PROF] self = cicli nella funzione stessa; incl = comprese le funzioni che chiama; kc = migliaia di cicli\r\n\r\n");

  printf("[PROF] ");
  prof_print_name("funzione", 26);
  printf("  chiamate  self_kc  self_pct   incl_kc  incl_pct  cicli/chiamata\r\n");

  // ordine per self decrescente
  int order[PROF_COUNT], n = 0;
  for (int i = 0; i < PROF_COUNT; i++)
    if (i != PROF_CALIB && (prof_calls[i] > 0 || prof_self[i] > 0)) order[n++] = i;
  for (int a = 0; a < n; a++)
    for (int b = a + 1; b < n; b++)
      if (prof_self[order[b]] > prof_self[order[a]]) { int t = order[a]; order[a] = order[b]; order[b] = t; }

  for (int k = 0; k < n; k++) {
    int i = order[k];
    printf("[PROF] ");
    prof_print_name(prof_names[i], 26);
    printf("  ");
    prof_print_num((uint32_t) prof_calls[i], 8);
    printf("  ");
    prof_print_num(prof_div(prof_self[i], 1000), 7);
    printf("  ");
    prof_print_pct(prof_pct10(prof_self[i], total), 8);
    printf("  ");
    if (i == PROF_OUTSIDE) {
      printf("        -         -               -");
    } else {
      prof_print_num(prof_div(prof_incl[i], 1000), 8);
      printf("  ");
      prof_print_pct(prof_pct10(prof_incl[i], total), 8);
      printf("  ");
      prof_print_num(prof_div(prof_incl[i], (uint32_t) (prof_calls[i] ? prof_calls[i] : 1)), 14);
    }
    printf("\r\n");
  }
  printf("[PROF] ================================================================\r\n");
}

#define PROF_INIT()                prof_init()
#define PROF_RESET()               prof_reset()
#define PROF_BEGIN(id)             prof_enter(id)
#define PROF_END(id)               prof_exit(id)
#define PROF_CALL(id, ...)         do { prof_enter(id); __VA_ARGS__; prof_exit(id); } while (0)
#define PROF_REQUEST_REPORT()      do { prof_report_pending = true; } while (0)
#define PROF_REPORT_IF_PENDING()   do { if (prof_report_pending) { prof_report(); prof_reset(); prof_report_pending = false; } } while (0)

#else   // OT_PROFILE == 0: nessun costo

#define PROF_INIT()                do {} while (0)
#define PROF_RESET()               do {} while (0)
#define PROF_BEGIN(id)             do {} while (0)
#define PROF_END(id)               do {} while (0)
#define PROF_CALL(id, ...)         do { __VA_ARGS__; } while (0)
#define PROF_REQUEST_REPORT()      do {} while (0)
#define PROF_REPORT_IF_PENDING()   do {} while (0)

#endif

// =====================================================================
// Motore AES (invariato rispetto al firmware originale)
// =====================================================================

uint32_t _aes_get_keyreg(uint32_t idx){
    uint32_t reg_offset[8*2] = {
        AES_KEY_SHARE0_0_REG_OFFSET, AES_KEY_SHARE0_1_REG_OFFSET,
        AES_KEY_SHARE0_2_REG_OFFSET, AES_KEY_SHARE0_3_REG_OFFSET,
        AES_KEY_SHARE0_4_REG_OFFSET, AES_KEY_SHARE0_5_REG_OFFSET,
        AES_KEY_SHARE0_6_REG_OFFSET, AES_KEY_SHARE0_7_REG_OFFSET,
        AES_KEY_SHARE1_0_REG_OFFSET, AES_KEY_SHARE1_1_REG_OFFSET,
        AES_KEY_SHARE1_2_REG_OFFSET, AES_KEY_SHARE1_3_REG_OFFSET,
        AES_KEY_SHARE1_4_REG_OFFSET, AES_KEY_SHARE1_5_REG_OFFSET,
        AES_KEY_SHARE1_6_REG_OFFSET, AES_KEY_SHARE1_7_REG_OFFSET
    };
    return reg_offset[idx];
}

uint32_t _aes_get_ivreg(uint32_t idx){
    uint32_t reg_offset[4] = {
        AES_IV_0_REG_OFFSET, AES_IV_1_REG_OFFSET,
        AES_IV_2_REG_OFFSET, AES_IV_3_REG_OFFSET
    };
    return reg_offset[idx];
}

uint32_t _aes_get_datainreg(uint32_t idx){
    uint32_t reg_offset[4] = {
        AES_DATA_IN_0_REG_OFFSET, AES_DATA_IN_1_REG_OFFSET,
        AES_DATA_IN_2_REG_OFFSET, AES_DATA_IN_3_REG_OFFSET
    };
    return reg_offset[idx];
}

// Configura il motore in CTR/256 bit con chiave e IV dati. Il contatore parte da `aes_iv`
// e avanza di 1 per ogni blocco elaborato.
void aes_init(uint32_t* aes_iv, uint32_t *aes_key) {

  mmio_region_t aes;
  uint32_t reg;

  PROF_CALL(PROF_ENTROPY_INIT, utils_entropy_init());

  aes = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR);

  // Reset the IP
  while(!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  reg = bitfield_bit32_write(0, AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT, true);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);
  reg = bitfield_bit32_write(0, AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT, true);
  reg = bitfield_bit32_write(reg, AES_TRIGGER_DATA_OUT_CLEAR_BIT, true);
  mmio_region_write32(aes, AES_TRIGGER_REG_OFFSET, reg);
  while (!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  reg = bitfield_field32_write(0, AES_CTRL_SHADOWED_OPERATION_FIELD,
                               AES_CTRL_SHADOWED_OPERATION_MASK);
  reg = bitfield_field32_write(reg, AES_CTRL_SHADOWED_MODE_FIELD,
                               AES_CTRL_SHADOWED_MODE_VALUE_AES_NONE);
  reg = bitfield_field32_write(reg, AES_CTRL_SHADOWED_KEY_LEN_FIELD,
                               AES_CTRL_SHADOWED_KEY_LEN_MASK);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);

  // Initialize AES IP configurations
  while(!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  reg = bitfield_field32_write(0, AES_CTRL_SHADOWED_OPERATION_FIELD,
                               AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC);
  reg = bitfield_field32_write(reg, AES_CTRL_SHADOWED_MODE_FIELD,
                               AES_CTRL_SHADOWED_MODE_VALUE_AES_CTR);
  reg = bitfield_field32_write(reg, AES_CTRL_SHADOWED_KEY_LEN_FIELD,
                               AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256);
  reg = bitfield_field32_write(reg, AES_CTRL_SHADOWED_PRNG_RESEED_RATE_FIELD,
                               AES_CTRL_SHADOWED_PRNG_RESEED_RATE_VALUE_PER_64);
  reg = bitfield_bit32_write(reg, AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT, false);
  reg = bitfield_bit32_write(reg, AES_CTRL_SHADOWED_SIDELOAD_BIT, false);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, AES_CTRL_SHADOWED_REG_OFFSET, reg);

  // Initialize AES IP auxiliary configurations
  reg = bitfield_bit32_write(0, AES_CTRL_AUX_SHADOWED_KEY_TOUCH_FORCES_RESEED_BIT, false);
  reg = bitfield_bit32_write(reg, AES_CTRL_AUX_SHADOWED_FORCE_MASKS_BIT, false);
  mmio_region_write32(aes, AES_CTRL_AUX_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, AES_CTRL_AUX_SHADOWED_REG_OFFSET, reg);
  mmio_region_write32(aes, AES_CTRL_AUX_REGWEN_REG_OFFSET, true);

  // Initialize key shares
  for (size_t i = 0; i < 8; i++) {
    mmio_region_write32(aes, _aes_get_keyreg(i), aes_key[i]);       // SHARE0 = key
    mmio_region_write32(aes, _aes_get_keyreg(i + 8), 0x00000000);   // SHARE1 = 0
  }

  reg = mmio_region_read32(aes, AES_CTRL_SHADOWED_REG_OFFSET);
  reg = bitfield_field32_read(reg, AES_CTRL_SHADOWED_MODE_FIELD);
  if (reg != AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB) {
      while(!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
      for (size_t i = 0; i < 4; i++) {
          mmio_region_write32(aes, _aes_get_ivreg(i), aes_iv[i]);
      }
  }
}

// =====================================================================
// CSRNG (invariato rispetto al firmware originale)
// =====================================================================

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
  reg = bitfield_field32_write(reg, EDN_CTRL_CMD_FIFO_RST_FIELD, kMultiBitBool4True);
  mmio_region_write32(edn0, EDN_CTRL_REG_OFFSET, reg);
  mmio_region_write32(edn0, EDN_CTRL_REG_OFFSET, EDN_CTRL_REG_RESVAL);

  // reset edn1
  reg = mmio_region_read32(edn1, EDN_CTRL_REG_OFFSET);
  reg = bitfield_field32_write(reg, EDN_CTRL_CMD_FIFO_RST_FIELD, kMultiBitBool4True);
  mmio_region_write32(edn1, EDN_CTRL_REG_OFFSET, reg);
  mmio_region_write32(edn1, EDN_CTRL_REG_OFFSET, EDN_CTRL_REG_RESVAL);

  // reset csrng
  mmio_region_write32(csrng, CSRNG_CTRL_REG_OFFSET, CSRNG_CTRL_REG_RESVAL);

  // reset entropy
  mmio_region_write32(entropy_src, ENTROPY_SRC_MODULE_ENABLE_REG_OFFSET,
                      ENTROPY_SRC_MODULE_ENABLE_REG_RESVAL);
  mmio_region_write32(entropy_src, ENTROPY_SRC_ENTROPY_CONTROL_REG_OFFSET,
                      ENTROPY_SRC_ENTROPY_CONTROL_REG_RESVAL);
  mmio_region_write32(entropy_src, ENTROPY_SRC_CONF_REG_OFFSET,
                      ENTROPY_SRC_CONF_REG_RESVAL);
  mmio_region_write32(entropy_src, ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_OFFSET,
                      ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_RESVAL);
  mmio_region_write32(entropy_src, ENTROPY_SRC_ALERT_THRESHOLD_REG_OFFSET,
                      ENTROPY_SRC_ALERT_THRESHOLD_REG_RESVAL);

  // entropy configure
  reg = bitfield_field32_write(0, ENTROPY_SRC_ENTROPY_CONTROL_ES_ROUTE_FIELD, kMultiBitBool4False);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_ENTROPY_CONTROL_ES_TYPE_FIELD, kMultiBitBool4False);
  mmio_region_write32(entropy_src, ENTROPY_SRC_ENTROPY_CONTROL_REG_OFFSET, reg);
  reg = bitfield_field32_write(0, ENTROPY_SRC_CONF_FIPS_ENABLE_FIELD, kMultiBitBool4True);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_CONF_ENTROPY_DATA_REG_ENABLE_FIELD, kMultiBitBool4False);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_CONF_THRESHOLD_SCOPE_FIELD, kMultiBitBool4True);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_CONF_RNG_BIT_ENABLE_FIELD, kMultiBitBool4False);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_CONF_RNG_BIT_SEL_FIELD, 4);
  reg = bitfield_field32_write(reg, ENTROPY_SRC_CONF_ENTROPY_DATA_REG_ENABLE_FIELD, kMultiBitBool4False);
  mmio_region_write32(entropy_src, ENTROPY_SRC_CONF_REG_OFFSET, reg);
  reg = bitfield_field32_write(ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_RESVAL,
                               ENTROPY_SRC_HEALTH_TEST_WINDOWS_FIPS_WINDOW_FIELD, 0x0200);
  mmio_region_write32(entropy_src, ENTROPY_SRC_HEALTH_TEST_WINDOWS_REG_OFFSET, reg);

  reg = bitfield_field32_write(0, ENTROPY_SRC_ALERT_THRESHOLD_ALERT_THRESHOLD_FIELD, 2);
  reg = bitfield_field32_write(2, ENTROPY_SRC_ALERT_THRESHOLD_ALERT_THRESHOLD_INV_FIELD, 0xFFFD);
  mmio_region_write32(entropy_src, ENTROPY_SRC_ALERT_THRESHOLD_REG_OFFSET, reg);
  mmio_region_write32(entropy_src, ENTROPY_SRC_MODULE_ENABLE_REG_OFFSET, kMultiBitBool4True);

  // configure csrng
  reg = bitfield_field32_write(0, CSRNG_CTRL_ENABLE_FIELD, kMultiBitBool4True);
  reg = bitfield_field32_write(reg, CSRNG_CTRL_SW_APP_ENABLE_FIELD, kMultiBitBool4True);
  reg = bitfield_field32_write(reg, CSRNG_CTRL_READ_INT_STATE_FIELD, kMultiBitBool4True);
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
  reg = bitfield_field32_write(reg, kAppCmdFieldFlag0, kMultiBitBool4False);
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

// =====================================================================
// SEZIONE A0 - Cache del motore AES: reinizializzazione completa solo se cambia la chiave
// =====================================================================

// aes_init() e' costosa (entropia, reset, configurazione, chiave, IV). Tra due segmenti con la
// stessa chiave basta riscrivere i 4 registri dell'IV a motore idle: il contatore riparte da li'.
static bool     aes_ready = false;      // il motore e' configurato con aes_cached_key
static uint32_t aes_cached_key[8];

// Da chiamare quando qualcosa puo' aver toccato il motore (INIT, fine rete):
// il prossimo segmento fara' un aes_init completo.
static void aes_invalidate(void) {
  aes_ready = false;
}

// Riposiziona solo il contatore. Il motore deve essere idle ed essere gia' configurato
// con la chiave giusta.
static void aes_set_iv(const uint32_t *iv) {
  mmio_region_t aes = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR);
  while (!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_IDLE_BIT));
  for (int i = 0; i < 4; i++)
    mmio_region_write32(aes, _aes_get_ivreg(i), iv[i]);
}

// Prepara il motore con chiave e contatore iniziale `iv`.
static void aes_start(uint32_t *iv, uint32_t *key) {
#if AES_FAST_IV
  if (aes_ready && memcmp(aes_cached_key, key, sizeof(aes_cached_key)) == 0) {
    PROF_CALL(PROF_AES_SET_IV, aes_set_iv(iv));   // stessa chiave: basta l'IV
    return;
  }
#endif
  PROF_CALL(PROF_AES_INIT, aes_init(iv, key));   // chiave nuova o motore da riconfigurare
  memcpy(aes_cached_key, key, sizeof(aes_cached_key));
  aes_ready = true;
}

// =====================================================================
// SEZIONE A - Contesti di cifratura: chi fornisce IV, chiave e base del contatore
// =====================================================================

// Tutto cio' che serve per cifrare/decifrare un segmento:
//   contatore del byte all'indirizzo L2 `a` = iv + (a - base) / 16
typedef struct {
  uint32_t iv[4];
  uint32_t key[8];
  uint32_t base;       // indirizzo L2 che corrisponde al blocco 0
} crypto_ctx_t;

// --- Attivazioni: una sola chiave e un solo IV, base = inizio dell'arena L2 ---

static crypto_ctx_t act_ctx;

// `words`: 4 parole di IV seguite da 8 parole di chiave (casuali, generate una volta all'avvio).
static void act_ctx_init(const uint32_t *words) {
  memcpy(act_ctx.iv,  words,     sizeof(act_ctx.iv));
  memcpy(act_ctx.key, words + 4, sizeof(act_ctx.key));
  act_ctx.base = L2_ARENA_BASE;
}

// --- Pesi: IV e chiave annunciati dal cluster, base = base del tensore ---

// Se `t` e' un tensore di pesi (noto alla hashmap), riempie il contesto e ritorna true.
// Altrimenti ritorna false senza toccare niente, e il trasferimento e' un'attivazione.
//   * tile successivi: il transfer_id e' gia' associato alla base del tensore
//   * primo tile: `src` e' la base annunciata con IV_MASK (si assume offset 0, come nel firmware
//     originale) e il transfer_id viene associato a quella base
static bool weights_ctx(const memory_transfer_operation_altered_t *t, crypto_ctx_t *ctx) {
  static uint32_t unused_iv[4];
  uint32_t tensor_base;

  if (hashmap_get_random((uint32_t) t->transfer_id, &tensor_base, unused_iv, NULL) == HM_FALSE) {
    if (hashmap_get_random((uint32_t) t->src, &tensor_base, unused_iv, NULL) == HM_FALSE)
      return false;
    hashmap_push_random((uint32_t) t->transfer_id, tensor_base, unused_iv, NULL);
  }

  uint32_t base;
  if (hashmap_get_random(tensor_base, &base, ctx->iv, ctx->key) == HM_FALSE)
    return false;

  ctx->base = base;
  return true;
}

// =====================================================================
// SEZIONE B - Un segmento: finestra di blocchi, AES in place, copia del solo segmento utile
// =====================================================================

// Il core OpenTitan vede la TCDM a passo 4 (difetto noto): la parola logica `i`,
// che il DMA scrive in modo lineare, e' all'indice i*4 della vista del core.
#define TCDM_WORD(i) (((volatile uint32_t *) TCDM_BASE)[(i) * 4])

static void dma_copy(uint32_t src, uint32_t dst, uint32_t size) {
  int id;
  PROF_BEGIN(PROF_DMA_ISSUE);
  id = idma_issue_1d(src, dst, size);
  PROF_END(PROF_DMA_ISSUE);
  PROF_BEGIN(PROF_DMA_WAIT);
  wait_for_idma_eot(id);
  PROF_END(PROF_DMA_WAIT);
}

// Cifra/decifra `nbytes` (multiplo di 16) a partire da TCDM_BASE, sul posto.
// Il motore e' gia' stato inizializzato: il contatore avanza da solo di 1 per blocco.
static void aes_ctr_in_place(uint32_t nbytes) {
  mmio_region_t aes = mmio_region_from_addr(TOP_EARLGREY_AES_BASE_ADDR);

  // Ciclo su 4 word alla volta
  for (uint32_t w = 0; w < nbytes / 4; w += 4) {
    for (int j = 0; j < 4; j++)
      // Le carico 4 per ogni ciclo interno nel motore AES
      mmio_region_write32(aes, _aes_get_datainreg(j), TCDM_WORD(w + j));

    PROF_BEGIN(PROF_AES_WAIT);
    while (!mmio_region_get_bit32(aes, AES_STATUS_REG_OFFSET, AES_STATUS_OUTPUT_VALID_BIT));
    PROF_END(PROF_AES_WAIT);

    for (int j = 0; j < 4; j++) {
      TCDM_WORD(w + j) = mmio_region_read32(aes, AES_DATA_OUT_0_REG_OFFSET + j * 4);

      // Lettura di servizio ereditata dal firmware originale (tcdm[j + count]).
      // Non rimuovere finche' non verificato sul TCDM.
      volatile uint32_t sink = ((volatile uint32_t *) TCDM_BASE)[w + j];
      (void) sink;
    }
  }
}

// Trasferisce `size` byte da `src` a `dst` cifrandoli o decifrandoli.
// Uno dei due indirizzi sta in L2 (src se si decifra, dst se si cifra) e decide il contatore.
static void crypt_segment(crypto_ctx_t *ctx, uint32_t src, uint32_t dst, uint32_t size, bool decrypt) {
  uint32_t l2_addr = decrypt ? src : dst;
  uint32_t offset  = l2_addr - ctx->base;
  uint32_t head    = offset % 16;                    // posizione del primo byte dentro il blocco
  uint32_t block   = offset / 16;                    // blocco che contiene il primo byte
  uint32_t nbytes  = (head + size + 15) & ~15u;      // blocchi interi che toccano il segmento

  uint32_t iv[4];                                    // copia: l'IV del contesto non va modificato
  memcpy(iv, ctx->iv, sizeof(iv));
  if (block != 0)
    PROF_CALL(PROF_ADD_IV, add_u128_leword_visual(iv, block));
  PROF_CALL(PROF_AES_START, aes_start(iv, ctx->key));

  uint32_t window = (uint32_t) TCDM_BASE + head;     // il dato entra nella finestra a offset head
  PROF_CALL(PROF_DMA_IN, dma_copy(src, window, size));   // byte prima e dopo: spazzatura, e va bene
  PROF_CALL(PROF_AES_LOOP, aes_ctr_in_place(nbytes));
  #if OT_DEBUG 
    if(decrypt){
      printf("Decrypted payload : ");
      for(int i = 0; i < size / 4; i++){
        printf("%d ",TCDM_WORD(i));
      }
      printf("\r\n");
    }
  #endif
  PROF_CALL(PROF_DMA_OUT, dma_copy(window, dst, size));  // fuori solo il segmento utile
}

// =====================================================================
// SEZIONE C - Trasferimenti
// =====================================================================

// Un trasferimento sicuro, 1D o 2D: ogni riga e' un segmento a se' (nessun buffering).
//   decifratura (L2 -> L1): la sorgente ha lo stride, la destinazione e' compatta
//   cifratura   (L1 -> L2): la sorgente e' compatta, la destinazione ha lo stride
static void secure_transfer(memory_transfer_operation_altered_t *t, bool decrypt, bool geometry) {
  uint32_t len      = geometry ? (uint32_t) t->size_1d     : (uint32_t) t->size;
  uint32_t reps     = geometry ? (uint32_t) t->repetitions : 1;
  uint32_t src_step = decrypt ? (uint32_t) t->src_stride : len;
  uint32_t dst_step = decrypt ? len : (uint32_t) t->dst_stride;

  // Pesi (noti alla hashmap) oppure attivazioni (chiave unica). I pesi si decifrano soltanto.
  crypto_ctx_t ctx;
  bool is_weights = false;
  // Nel caso in cui si stia decifrando, controlla che il trasferimento sia di pesi 
  // Se lo è, riempi il crypto context, altrimenti vai avanti e tratta come attivazioni
  if (decrypt) {
    PROF_BEGIN(PROF_WEIGHTS_CTX);
    is_weights = weights_ctx(t, &ctx);
    PROF_END(PROF_WEIGHTS_CTX);
  }
  // Se si tratta di attivazioni, riempi il ctx locale con il ctxt globale dedicato alle attivazioni
  // Si considera un solo IV globale, calcolato partendo dall'inizio di L2
  if (!is_weights) {
    uint32_t l2_addr = decrypt ? (uint32_t) t->src : (uint32_t) t->dst;
    if (l2_addr < L2_ARENA_BASE) fatal("trasferimento cifrato fuori dall'arena L2");
    ctx = act_ctx;
  }
  // Cifra/Decifra il payload, visto che le operazioni sono equivalenti 
  // Non c'è estensione o aggiustamento degli indirizzi grazie alle proprietà di AES_CTR
  // Per uniformità ogni trasferimento è trattato come un 2D, per poi ricardere in 1D se reps == 1
  for (uint32_t i = 0; i < reps; i++) {
    PROF_CALL(PROF_CRYPT_SEGMENT,
              crypt_segment(&ctx,
                            (uint32_t) t->src + i * src_step,
                            (uint32_t) t->dst + i * dst_step,
                            len, decrypt));
  }
}

static void plain_transfer(const memory_transfer_operation_altered_t *t, bool geometry) {
  if (!geometry) {
    dma_copy((uint32_t) t->src, (uint32_t) t->dst, (uint32_t) t->size);
  } else if (t->repetitions == 1) {
    dma_copy((uint32_t) t->src, (uint32_t) t->dst, (uint32_t) t->size_1d);
  } else {
    issue_idma_2d_emulated_strided((uint32_t) t->src, (uint32_t) t->dst,
                                   (uint32_t) t->size_1d,
                                   (uint32_t) t->src_stride, (uint32_t) t->dst_stride,
                                   (uint32_t) t->repetitions);
  }
}

// =====================================================================
// SEZIONE D - Messaggi dal cluster / CVA6, interrupt, main
// =====================================================================

static const dif_hmac_transaction_t kHmacTransactionConfig = {
    .digest_endianness = kDifHmacEndiannessLittle,
    .message_endianness = kDifHmacEndiannessLittle,
};

static void test_setup(mmio_region_t base_addr, dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_init(base_addr, hmac));
}

// If `key` == NULL use SHA256 mode, otherwise use the provided key in HMAC mode.
static void test_start(const dif_hmac_t *hmac, const uint8_t *key) {
  if (key == NULL) {
    CHECK_DIF_OK(dif_hmac_mode_sha256_start(hmac, kHmacTransactionConfig));
  } else {
    CHECK_DIF_OK(dif_hmac_mode_hmac_start(hmac, key, kHmacTransactionConfig));
  }
}

static void run_hmac(const dif_hmac_t *hmac) {
  CHECK_DIF_OK(dif_hmac_process(hmac));
}

static int run_test(const dif_hmac_t *hmac, const char *data, size_t len,
                    const uint8_t *key, uint32_t *expected_digest) {
  dif_hmac_digest_t digest;

  test_start(hmac, key);
  hmac_testutils_push_message(hmac, data, len);
  hmac_testutils_fifo_empty_polled(hmac);
  hmac_testutils_check_message_length(hmac, len * 8);
  run_hmac(hmac);

  // attende il risultato e lo salva in digest.digest
  hmac_testutils_finish_polled(hmac, &digest);
  int j = 0;
  for (int i = 7; i >= 0; i--) {
    if (swap_endianness((uint32_t) digest.digest[i]) != expected_digest[j++])
      return -1;
  }
  return 1;
}

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

static void handle_init(const memory_transfer_operation_altered_t *t, uint32_t flags) {
  if (flags & CLEAR_MASK)
    return;

  PROF_RESET();                          // il profilo copre una rete: da INIT a fine
  rng_buffer_init();
  aes_invalidate();

  // t->src: chiave AES dei pesi, t->dst: chiave HMAC
  for (int i = 0; i < 8; i++) {
    AesKey[i]   = ((uint32_t *) t->src)[i];
    kHmacKey[i] = ((uint32_t *) t->dst)[i];
  }
}

static void handle_hmac(const memory_transfer_operation_altered_t *t) {
  dif_hmac_t hmac;
  test_setup(mmio_region_from_addr(TOP_EARLGREY_HMAC_BASE_ADDR), &hmac);

  // t->src = indirizzo dei pesi, t->dst = digest atteso, t->size = lunghezza dei pesi
  if (run_test(&hmac, (const char *) t->src, t->size, (uint8_t *) kHmacKey, (uint32_t *) t->dst) < 0)
    printf("[OT] HMAC check failed! Stopping network execution...");
}

// Il cluster annuncia IV e chiave di un tensore di pesi: t->src = base del tensore,
// t->dst = puntatore alle 4 parole dell'IV.
static void handle_iv(const memory_transfer_operation_altered_t *t) {
  static uint32_t iv[4];   // statico: la hashmap potrebbe tenere il puntatore
  for (int i = 0; i < 4; i++)
    iv[i] = ((uint32_t *) t->dst)[i];
  hashmap_push_random((uint32_t) t->src, (uint32_t) t->src, iv, AesKey);
}

static void handle_transfer(memory_transfer_operation_altered_t *t, uint32_t flags) {
  // Indirizzi relativi al cluster -> indirizzi globali
  // Probabilmente non è necessario
  // if (t->src < CLUSTER_ADDR_LIMIT) {
  //   t->src += CLUSTER_SPM_BASE_ADDR;
  // } else if (t->dst < CLUSTER_ADDR_LIMIT) {
  //   t->dst += CLUSTER_ADDR_LIMIT;
  // }

  bool geometry = flags & GEOMETRY_MASK;

  if (flags & SECURE_MASK)
    PROF_CALL(PROF_SECURE, secure_transfer(t, flags & OPERATION_MASK, geometry));
  else
    PROF_CALL(PROF_PLAIN, plain_transfer(t, geometry));
}

// Gestisce un messaggio. Ritorna true se bisogna avvisare il cluster a fine operazione.
static bool handle_message(uint32_t letter0, uint32_t letter1) {
  memory_transfer_operation_altered_t *t = (memory_transfer_operation_altered_t *) letter0;

#if OT_DEBUG
  debug_print_transfer(letter0, letter1);
#endif

  if (letter1 & HOST_MASK) {
    // Richiesta da CVA6: avvia il cluster. letter0 = indirizzo di boot.
    PROF_BEGIN(PROF_MSG_HOST);
    asm volatile("":::"memory");
    *(volatile uint32_t*)(0x7800FF00) = 0xFFFFFFF0;
    asm volatile("":::"memory");
    pulp_cluster_kick_off((void *) letter0);
    PROF_END(PROF_MSG_HOST);
    return false;
  }

  if (letter1 & END_MASK) {
    // Il cluster ha finito: letter0 == 0 se la rete e' andata a buon fine.
    PROF_BEGIN(PROF_MSG_END);
    hashmap_init();
    aes_invalidate();
    PROF_END(PROF_MSG_END);
    PROF_REQUEST_REPORT(); 
    // mailbox_send(7, letter0, letter1);
    // mb_write(0x1, MBOX_CAR_INT_SND_SET(7));              // il riepilogo si stampa a fine handler
    return false;
  }

  if (letter1 & INIT_MASK) { PROF_CALL(PROF_MSG_INIT, handle_init(t, letter1)); return true; }
  if (letter1 & HMAC_MASK) { PROF_CALL(PROF_MSG_HMAC, handle_hmac(t));          return true; }
  if (letter1 & IV_MASK)   { PROF_CALL(PROF_MSG_IV,   handle_iv(t));            return true; }

  handle_transfer(t, letter1);
  return true;
}

static void notify_cluster(void) {
  uint32_t *eu_addr = (uint32_t *) eu_evt_trig_cluster_addr(IDMA_EVENT);   // doorbell dell'Event Unit
  *eu_addr = 0x1;                                                          // coreSet mask: core 0
}

void external_irq_handler(void) {
#ifdef OT_BENCHMARK
  uint32_t start_cycles = ibex_mcycle_read();
#endif
  PROF_BEGIN(PROF_IRQ);

  uint32_t iid = *PLIC_CLAIM_COMPLETE;
  if (iid == 0) {
    PROF_END(PROF_IRQ);
    return;
  }

  if (iid == MAILBOX_IRQ_ID) {
    uint32_t letter0 = 0x0;   // indirizzo della struct del trasferimento
    uint32_t letter1 = 0x0;   // tipo di trasferimento (flag)

    PROF_BEGIN(PROF_MAILBOX);
    mb_write(0x1, MBOX_CAR_INT_RCV_CLR(1));
    mb_write(0x1, MBOX_CAR_INT_SND_CLR(1));
    mailbox_read(1, &letter0, &letter1);
    PROF_END(PROF_MAILBOX);

    // Funzione bloccante che si occupa della gestione del messaggio
    // La funzione ritorna solo quando l'operazione è finita 
    // IDEA : Si potrebbe creare una variante che ritorna anticipatamente per creare trasferimenti e cifratura async
    bool notify = handle_message(letter0, letter1);

#ifdef OT_BENCHMARK
    printf("[OT BENCHMARKING] letter1 = %x, cycles = %d\r\n", letter1, (ibex_mcycle_read() - start_cycles));
#endif

    if (notify)
      PROF_CALL(PROF_NOTIFY, notify_cluster());
  }

  *PLIC_CLAIM_COMPLETE = iid;
  PROF_END(PROF_IRQ);

  PROF_REPORT_IF_PENDING();             // dopo aver chiuso l'handler: la stampa non sporca la misura
}

int main(int argc, char **argv) {

  //WARNING: rom/silicon_creator/uart.h has been modified to support astral architecture
  astral_uart_init(50000000, 115200);

  hashmap_init();
  PROF_INIT();

  // PLIC e interrupt
  printf("OpenTitan: PLIC set UP...\r\n");

  unsigned val = 0xe0000001;
  asm volatile("csrw mtvec, %0\n" : : "r"(val));     // vettore degli interrupt in SRAM

  unsigned val_1 = 0x00001808;                       // global interrupt enable
  unsigned val_2 = 0x00000800;                       // external interrupts
  asm volatile("csrw  mstatus, %0\n" : : "r"(val_1));
  asm volatile("csrw  mie, %0\n"     : : "r"(val_2));

  int volatile *plic_prio = (int *) 0xC800027C;      // priority reg
  int volatile *plic_en   = (int *) 0xC8002010;      // enable reg
  *plic_prio = 1;                                    // priorita' dell'interrupt della mailbox
  *plic_en   = 0x80000000;                           // abilita l'interrupt

  // Chiave e IV delle attivazioni: una volta sola, all'avvio (la rete non ha ancora girato)
  // Genera ACT_RANDOM_WORDS = 12 word da 32 bit random, le funzioni sono rimodellate ma operano come quelle nel firmware hand-made
  rng_buffer_init();
  utils_csrng_randgen(&rng, ACT_RANDOM_WORDS);
  // Inizializza il context di cifratura, contenente chiave e IV generati all'avvio di OpenTitan
  act_ctx_init((const uint32_t *) rng.data);

  while (1) {
      asm volatile("fence rw,rw" ::: "memory");
      asm volatile("wfi" ::: "memory");
      asm volatile("fence rw,rw" ::: "memory");
  }

  return 0;
}