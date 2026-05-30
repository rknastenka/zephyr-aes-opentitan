#define DT_DRV_COMPAT lowrisc_opentitan_aes

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/crypto/cipher.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/sys_io.h>

LOG_MODULE_REGISTER(opentitan_aes, CONFIG_CRYPTO_LOG_LEVEL);

/* Base Offsets for Registers (Keys, IV, Data) */
#define AES_KEY_SHARE0_0_REG_OFFSET 0x4
#define AES_KEY_SHARE1_0_REG_OFFSET 0x24
#define AES_IV_0_REG_OFFSET 0x44
#define AES_DATA_IN_0_REG_OFFSET 0x54
#define AES_DATA_OUT_0_REG_OFFSET 0x64

/* Control Register & Bitmasks */
#define AES_CTRL_SHADOWED_REG_OFFSET 0x74
#define AES_CTRL_SHADOWED_OPERATION_OFFSET 0
#define AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC 0x1
#define AES_CTRL_SHADOWED_OPERATION_VALUE_AES_DEC 0x2

#define AES_CTRL_SHADOWED_MODE_OFFSET 2
#define AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB 0x1
#define AES_CTRL_SHADOWED_MODE_VALUE_AES_CBC 0x2
#define AES_CTRL_SHADOWED_MODE_VALUE_AES_CTR 0x10

#define AES_CTRL_SHADOWED_KEY_LEN_OFFSET 8
#define AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_128 0x1
#define AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256                                \
  0x4 /* will not support AES-192 in v1, 128 and 256 are enough for now,       \
         192-bit keys are not commonly used in practice. */

#define AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT 15

/* Trigger Register */
#define AES_TRIGGER_REG_OFFSET 0x80
#define AES_TRIGGER_START_BIT 0
#define AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT 1
#define AES_TRIGGER_DATA_OUT_CLEAR_BIT 2

/* Status Register */
#define AES_STATUS_REG_OFFSET 0x84
#define AES_STATUS_IDLE_BIT 0
#define AES_STATUS_OUTPUT_VALID_BIT 3
#define AES_STATUS_INPUT_READY_BIT 4

struct opentitan_aes_config {
  mm_reg_t base_addr;
};

struct opentitan_aes_session {
  bool in_use;
  const struct device *dev;
  enum cipher_op dir; /* operation: encrypt/decrypt */
                      /* in zephyr APIs, 0=dec, 1=enc. */
  /* opentitan CTRL Reg space needs 0x1 for enc, 0x2 for dec. */
  /* We map these in the mode operation functions. */
  uint32_t reg_ctrl_key_len; /* key length: 128/256 -- pre-shifted to bits
                                [11:8] of CTRL */
  uint32_t key_words_count;  /* 4 = AES-128, 8 = AES-256 */
  uint32_t key_words[8];     /* register to store the key (8 words * 32bits =
                                256-bit max key) */
};

/* Mutex and Semaphore for Thread Safety and Synchronization */
/* prevent race conditions when multiple threads access the same AES hardware */
struct opentitan_aes_data {
  struct k_mutex lock; /* Prevents concurrent aes access across threads */
  /* since we are doing polling in this driver, we don't need the semaphore */
  /* it's a design choice by opentitan AES, it doesn't have an interrupt line to
   * signal when the operation is done */

  struct opentitan_aes_session sessions[CONFIG_CRYPTO_OPENTITAN_MAX_SESSION];
};

#define AES_TIMEOUT_US 10000

static int poll_idle(mm_reg_t base) {
  uint32_t t = 0;
  while (!(sys_read32(base + AES_STATUS_REG_OFFSET) &
           (1u << AES_STATUS_IDLE_BIT))) {
    if (t++ > (AES_TIMEOUT_US / 10)) {
      return -ETIMEDOUT;
    }
    k_busy_wait(10);
  }
  return 0;
}

/*
 * Hardware-level flush.
 * - Clears keys, IVs, and data registers and returns hardware to IDLE.
 * - Called at boot and during session teardown to prevent key leakage.
 */
static int opentitan_aes_hw_flush(mm_reg_t base) {
  int ret;

  /* Wait for IDLE before touching Control Register */
  /* Writes to Control Register are silently ignored if hardware is not idle */
  ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  /* Set MANUAL_OPERATION=1 to disable autostart the enc/dec */
  /* (noted in opentitan AES HW docs to be required for a successful flush) */
  /* we will set the MANUAL_OPERATION back to zero in the begin_session() */
  /* because we want the autostart feature for normal encryption/decryption
   * operations */
  /* we only need to disable it for the flush operation at boot and during
   * session teardown. */
  uint32_t ctrl_val = (1u << AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT);
  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
  sys_write32(ctrl_val,
              base + AES_CTRL_SHADOWED_REG_OFFSET); /* Double-write required for
                                                       all shadowed registers */

  /* Re-poll IDLE bcz control register write may trigger an internal PRNG reseed
   */
  ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  /* Trigger hardware clear of keys, IVs, and all data registers */
  sys_write32((1 << AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT) |
                  (1 << AES_TRIGGER_DATA_OUT_CLEAR_BIT),
              base + AES_TRIGGER_REG_OFFSET);

  /* Wait for IDLE after clear completes */
  /* The hardware clear takes several clock cycles to overwrite all registers
   * with PRNG-generated data. */
  return poll_idle(base);
}

/* Zephyr device initialization callback */
static int opentitan_aes_init(const struct device *dev) {
  struct opentitan_aes_data *data = dev->data;
  const struct opentitan_aes_config *cfg = dev->config;

  k_mutex_init(&data->lock);

  /* Clear all software session slots */
  for (int i = 0; i < CONFIG_CRYPTO_OPENTITAN_MAX_SESSION; i++) {
    data->sessions[i].in_use = false;
    memset(data->sessions[i].key_words, 0, sizeof(data->sessions[i].key_words));
  }

  /* Flush hardware state at boot */
  int ret = opentitan_aes_hw_flush(cfg->base_addr);
  if (ret != 0) {
    LOG_ERR("OpenTitan AES hardware flush failed (timed out)");
    return ret;
  }

  LOG_INF("OpenTitan AES driver initialized.");
  return 0;
}

/* effective_key = SHARE0 XOR SHARE1 */
static void aes_write_key(
    mm_reg_t base,
    const uint32_t
        *key_words, /* word=32bits // AES-128 gives 4 words, AES-256 gives 8 */
    uint32_t key_word_count) /* How many of those words above are real key
                                material (4 or 8), rest is padding */
{
  /* share0-share7 */
  for (int i = 0; i < 8; i++) { /* The loop always runs 8 times, all 8 register
                                   slots must be written */
    uint32_t share0_word =
        (i < (int)key_word_count)
            ? key_words[i]
            : 0u; /* if i is less than the actual key word count, write the real
                     key word; otherwise write zero for padding */
    if (i < (int)key_word_count) {
      LOG_DBG("KEY_SHARE0_%d = 0x%08x", i, share0_word);
    }
    sys_write32(
        share0_word,
        base + AES_KEY_SHARE0_0_REG_OFFSET +
            i * 4); /* jump 4bytes to go to the next SHARE0_i register */
  }

  /* SHARE1 is always zero in v1 (no side-channel masking). */
  /* If we later add support for masked keys, this loop can be modified to write
   * the actual share1 words instead of zeros. */
  for (int i = 0; i < 8; i++) {
    sys_write32(0u, base + AES_KEY_SHARE1_0_REG_OFFSET + i * 4);
  }
}

static void aes_write_iv(mm_reg_t base, const uint32_t *iv_words) {
  for (int i = 0; i < 4; i++) {
    sys_write32(iv_words[i], base + AES_IV_0_REG_OFFSET + i * 4);
  } /* IV_0..IV_3 //IV is always 128 bits */
}

static void
aes_write_block(mm_reg_t base,
                const uint8_t *src) /* Pointer to the 16-byte input block */
/* src is uint8_t, not uint32_t like the key and IV. */
/* That's because the Zephyr crypto API gives you a raw byte buffer
   (pkt->in_buf), */
/* not a pre-chunked word array. */
{
  for (int i = 0; i < 4; i++) {
    uint32_t word = sys_get_le32(src + i * 4);
    LOG_DBG("DATA_IN_%d = 0x%08x", i, word);
    sys_write32(word, base + AES_DATA_IN_0_REG_OFFSET + i * 4);
  }
}

/* * Why sys_get_le32() instead of a cast to uint32_t *? */
/* It reads 4 bytes starting at src + i*4 and assembles them into a uint32_t in
 * little-endian order. It solves two problems at once: */
/*
  Problem 1 — Alignment. pkt->in_buf is a uint8_t *.
  If you tried to cast it directly to uint32_t * and read it,
  you might crash on hardware that requires 4-byte aligned reads.
  sys_get_le32 reads byte-by-byte internally so alignment doesn't matter.
*/
/*
Problem 2 — Endianness. The AES DATA_IN registers expect little-endian words.
sys_get_le32 guarantees that byte 0 of your input ends up in bits 0–7 of the
word, byte 1 in bits 8–15, and so on. regardless of whether the CPU is big or
little endian.
*/

static void aes_read_block(mm_reg_t base, uint8_t *dst) {
  for (int i = 0; i < 4; i++) {
    uint32_t word = sys_read32(base + AES_DATA_OUT_0_REG_OFFSET + i * 4);
    LOG_DBG("DATA_OUT_%d raw = 0x%08x", i, word);
    sys_put_le32(word, dst + i * 4);
  }
}
/*
 * The caller must have already verified OUTPUT_VALID=1.  Reading all
 * four DATA_OUT registers is mandatory — the hardware will not start
 * processing the next block until every output word has been consumed.
 * (This is the hardware's "do not overwrite un-read output" interlock.)
 *
 * We use sys_put_le32() as the symmetric inverse of sys_get_le32() in
 * aes_write_block().  The DATA_OUT registers are little-endian, so
 * sys_put_le32() writes bytes in the correct order to dst regardless of
 * the host CPU's endianness.
 */

/* ------------------------------------------------------ */
/* AES Modes - ECB, CBC, CTR */
/* ------------------------------------------------------ */

/* loop until STATUS.INPUT_READY (bit 4) is set, meaning the hardware */
/* has consumed the previous DATA_IN write and is ready for a new block. */
static int poll_input_ready(mm_reg_t base) {
  uint32_t t = 0;

  while (!(sys_read32(base + AES_STATUS_REG_OFFSET) &
           (1u << AES_STATUS_INPUT_READY_BIT))) {
    if (t++ > (AES_TIMEOUT_US / 10)) {
      return -ETIMEDOUT;
    }
    k_busy_wait(10);
  }
  return 0;
}

/* loop until STATUS.OUTPUT_VALID (bit 3) is set, meaning the hardware */
/* has finished processing a block and the result is ready in DATA_OUT. */
static int poll_output_valid(mm_reg_t base) {
  uint32_t t = 0;

  while (!(sys_read32(base + AES_STATUS_REG_OFFSET) &
           (1u << AES_STATUS_OUTPUT_VALID_BIT))) {
    if (t++ > (AES_TIMEOUT_US / 10)) {
      return -ETIMEDOUT;
    }
    k_busy_wait(10);
  }
  return 0;
}

/* --- ECB mode --- */
/* Process the input data in 16-byte blocks */
/* writing each block to the AES_DATA_IN registers */
/* and reading the result from AES_DATA_OUT after each block is processed. */
static int
opentitan_aes_ecb_op(struct cipher_ctx *ctx,
                     struct cipher_pkt *pkt) /* these are zephyr API structs */
/* // cipher_ctx has the session pointer and mode parameters (like IV pointer
   for CBC) */
{ /* cipher_pkt has the input and output buffers and lengths */
  //                                                                              // REF: https://docs.zephyrproject.org/latest/doxygen/html/structcipher__ctx.html
  const struct opentitan_aes_session *sess =
      (const struct opentitan_aes_session *)ctx->drv_sessn_state;
  const struct opentitan_aes_config *cfg =
      (const struct opentitan_aes_config *)sess->dev->config;
  mm_reg_t base = cfg->base_addr;

  /* ECB has no padding in v1 - caller must supply one or more complete 16-byte
   * blocks. */
  if (pkt->in_len == 0 ||
      (pkt->in_len % 16) !=
          0) { /* in_len: Number of input **bytes** to process. */
    return -EINVAL;
  }

  uint32_t num_blocks =
      pkt->in_len / 16; /* number of 16-byte(128bits) blocks to process, used
                           for loop control below */

  /* We set up the control register once at the start of the operation, */
  /* and the hardware remains configured for the entire message. */
  uint32_t op_val = (sess->dir == CRYPTO_CIPHER_OP_ENCRYPT)
                        ? AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC
                        : AES_CTRL_SHADOWED_OPERATION_VALUE_AES_DEC;

  uint32_t ctrl_val =
      (op_val << AES_CTRL_SHADOWED_OPERATION_OFFSET) | /* OPERATION */
      (AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB
       << AES_CTRL_SHADOWED_MODE_OFFSET) | /* MODE */
      sess->reg_ctrl_key_len; /* pre-shifted to bits [11:8] by begin_session //
                                 KEY_LEN */
  LOG_DBG("CTRL_SHADOWED = 0x%08x", ctrl_val);
  LOG_DBG("OPERATION = %d, MODE = %d, KEY_LEN = %d", (ctrl_val & 0x3),
          ((ctrl_val >> AES_CTRL_SHADOWED_MODE_OFFSET) & 0x3f),
          ((ctrl_val >> AES_CTRL_SHADOWED_KEY_LEN_OFFSET) & 0xff));

  /*
   * Bit layout:
   *   [1:0]  OPERATION  — op_val (1=enc, 2=dec)
   *   [7:2]  MODE       — AES_ECB shifted to bits [7:2]
   *   [11:8] KEY_LEN    — sess->reg_ctrl_key_len (pre-shifted by begin_session)
   *   [15]   MANUAL_OP  — 0 (autostart enabled)
   */

  /* Wait for IDLE before touching Control Register */
  /* Writes to Control Register are silently ignored if hardware is not idle */
  int ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  LOG_DBG("Before writing CTRL");
  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET); /* shadowed */
  LOG_DBG("After writing CTRL, STATUS=0x%08x",
          sys_read32(base + AES_STATUS_REG_OFFSET));

  /* Wait for IDLE after writing CTRL. */
  /* A CTRL write may trigger an internal PRNG reseed. */
  /* Key writes issued before IDLE is set are silently ignored. */
  ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }
  /*
   * Opentitan REF: Since writing this register may initiate the reseeding of
   * the internal PRNGs, software must check that the AES unit is idle before
   * providing the initial key.
   */

  /* Write the key after confirming the hardware is ready to accept it. */
  aes_write_key(base, sess->key_words,
                sess->key_words_count); /* block 0 - outside the loop */

  /* check INPUT_READY reg before writing the first block */
  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  /* write the first block to start the encryption/decryption */
  aes_write_block(base, pkt->in_buf); /* block 0 — hardware auto-starts */

  /* Wait for block 0 to be latched before optionally pre-loading block 1. */
  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  /* Pre-load block 1 if present (pipeline warm-up). */
  if (num_blocks > 1) {
    aes_write_block(base, pkt->in_buf + 16);
  }

  for (uint32_t i = 0; i < num_blocks; i++) {
    ret = poll_output_valid(base);
    if (ret) {
      return ret;
    }

    /* Read all *four* DATA_OUT words(16bytes), must to release interlock so it
     * can accept the next block. */
    aes_read_block(base, pkt->out_buf + i * 16);

    /* send a new block every time we read a block */
    /* so the hardware can process blocks in a pipeline (enc/dec of block N
     * overlaps with enc/dec of block N+1) */
    if (i + 2 < num_blocks) {
      aes_write_block(base, pkt->in_buf + (i + 2) * 16);
    }
  }
  /* out_buf: [ encrypted block 0 ][ encrypted block 1 ] ... */

  return 0;
}
/*
 * Note: OpenTitan programmer's guide: INPUT_READY is guaranteed to be 1
 * when OUTPUT_VALID is 1. After  poll_output_valid() + aes_read_block(),
 * the next aes_write_block() needs no extra poll_input_ready() call

there's indeed a one cycle gap here, but we're writing software, we don't care
much about it
*/

/* --- CBC mode --- */
/* similar to ECB but with the IV handling */
static int opentitan_aes_cbc_op(struct cipher_ctx *ctx, struct cipher_pkt *pkt,
                                uint8_t *iv) {
  const struct opentitan_aes_session *sess =
      (const struct opentitan_aes_session *)ctx->drv_sessn_state;
  const struct opentitan_aes_config *cfg =
      (const struct opentitan_aes_config *)sess->dev->config;
  mm_reg_t base = cfg->base_addr;

  /* CBC requires a 16-byte IV. */
  if (iv == NULL) {
    LOG_ERR("CBC mode requires a non-NULL IV");
    return -EINVAL;
  }

  /* Input must be a non-empty multiple of 16 bytes. */
  if (pkt->in_len == 0 || (pkt->in_len % 16) != 0) {
    return -EINVAL;
  }

  uint32_t num_blocks = pkt->in_len / 16;
  const uint8_t *iv_bytes = iv;

  uint32_t op_val = (sess->dir == CRYPTO_CIPHER_OP_ENCRYPT)
                        ? AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC
                        : AES_CTRL_SHADOWED_OPERATION_VALUE_AES_DEC;

  uint32_t ctrl_val =
      (op_val << AES_CTRL_SHADOWED_OPERATION_OFFSET) | /* OPERATION */
      (AES_CTRL_SHADOWED_MODE_VALUE_AES_CBC
       << AES_CTRL_SHADOWED_MODE_OFFSET) | /* MODE */
      sess->reg_ctrl_key_len; /* pre-shifted to bits [11:8] by begin_session //
                                 KEY_LEN */
  LOG_DBG("CTRL_SHADOWED = 0x%08x", ctrl_val);

  /* Wait for IDLE before writing CTRL. */
  int ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);

  ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  aes_write_key(base, sess->key_words, sess->key_words_count);

  /* Load the IV: */
  /* For encryption: this is the user-supplied IV for the first block. */
  /* For decryption: this is also the user-supplied IV for the first block. */
  uint32_t iv_words[4];
  for (int i = 0; i < 4; i++) {
    iv_words[i] = sys_get_le32(iv_bytes + i * 4);
  }
  aes_write_iv(base, iv_words);
  /*
   * Software MUST NOT re-write IV
   * between blocks of the same message.
   *
   * Ref: OpenTitan AES Theory of Operation, Datapath step 7:
   *   "If running in CBC mode, the IV registers are updated with the output
   *    data (encryption) or the value stored in the previous input data
   *    register (decryption)."
   * https://opentitan.org/book/hw/ip/aes/doc/theory_of_operation.html
   */

  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  aes_write_block(base, pkt->in_buf);

  /* Wait for block 0 to be latched before optionally pre-loading block 1. */
  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  /* Pre-load block 1 if present (pipeline warm-up). */
  if (num_blocks > 1) {
    aes_write_block(base, pkt->in_buf + 16);
  }

  /* Pipeline loop: read output N, write input N+2. */
  for (uint32_t i = 0; i < num_blocks; i++) {
    ret = poll_output_valid(base);
    if (ret) {
      return ret;
    }

    aes_read_block(base, pkt->out_buf + i * 16);

    if (i + 2 < num_blocks) {
      aes_write_block(base, pkt->in_buf + (i + 2) * 16);
    }
  }

  return 0;
}

/* ---- CTR mode: ---- */
/* Key differences from CBC: */
/* - No padding required: CTR works on any input length. The last block */
/* may be partial — the hardware XORs only the valid bytes. */
/* - Hardware auto-increments the counter after each block — software */
/* must NOT re-write the IV between blocks of the same message. */
static int opentitan_aes_ctr_op(struct cipher_ctx *ctx, struct cipher_pkt *pkt,
                                uint8_t *ctr) {
  const struct opentitan_aes_session *sess =
      (const struct opentitan_aes_session *)ctx->drv_sessn_state;
  const struct opentitan_aes_config *cfg =
      (const struct opentitan_aes_config *)sess->dev->config;
  mm_reg_t base = cfg->base_addr;

  if (ctr == NULL) {
    LOG_ERR("CTR mode requires a non-NULL counter/IV");
    return -EINVAL;
  }

  if (pkt->in_len == 0) {
    return -EINVAL;
  }

  uint32_t num_full_blocks = pkt->in_len / 16;
  uint32_t remainder = pkt->in_len % 16;

  uint32_t num_blocks = num_full_blocks + (remainder ? 1 : 0);

  /*
   * CTR mode always uses AES_ENC for the keystream generation,
   * regardless of whether the session is encrypting or decrypting.
   * The OPERATION field in CTRL must be AES_ENC (0x1).
   */
  uint32_t ctrl_val =
      (AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC
       << AES_CTRL_SHADOWED_OPERATION_OFFSET) |
      (AES_CTRL_SHADOWED_MODE_VALUE_AES_CTR << AES_CTRL_SHADOWED_MODE_OFFSET) |
      sess->reg_ctrl_key_len;

  LOG_DBG("CTR CTRL_SHADOWED = 0x%08x", ctrl_val);

  /* Wait for IDLE before writing CTRL. */
  int ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
  sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);

  /* Re-poll IDLE: CTRL write may trigger PRNG reseed. */
  ret = poll_idle(base);
  if (ret != 0) {
    return ret;
  }

  aes_write_key(base, sess->key_words, sess->key_words_count);

  /*
   * Load the initial counter value into IV_0..IV_3.
   * Hardware auto-increments after each block — do NOT re-write between blocks.
   */
  uint32_t iv_words[4];
  for (int i = 0; i < 4; i++) {
    iv_words[i] = sys_get_le32(ctr + i * 4);
  }
  aes_write_iv(base, iv_words);

  /* --- Pipeline loop (same pattern as ECB/CBC) --- */
  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  /*
   * For the partial last block, pad the input to 16 bytes with zeros,
   * feed the full padded block to hardware, then copy only 'remainder'
   * bytes from the output. The hardware always processes 128-bit blocks.
   */
  uint8_t padded_in[16] = {0};
  uint8_t padded_out[16] = {0};

  /* Write block 0. */
  if (num_full_blocks == 0) {
    memcpy(padded_in, pkt->in_buf, remainder);
    aes_write_block(base, padded_in);
    ret = poll_output_valid(base);
    if (ret) {
      return ret;
    }
    aes_read_block(base, padded_out);
    memcpy(pkt->out_buf, padded_out, remainder);
    return 0;
  }

  /* Write first full block — hardware auto-starts. */
  aes_write_block(base, pkt->in_buf);

  ret = poll_input_ready(base);
  if (ret) {
    return ret;
  }

  if (num_blocks > 1) {
    if (num_full_blocks > 1) {
      aes_write_block(base, pkt->in_buf + 16);
    } else {
      /* Block 1 is the partial block. */
      memset(padded_in, 0, sizeof(padded_in));
      memcpy(padded_in, pkt->in_buf + 16, remainder);
      aes_write_block(base, padded_in);
    }
  }

  /* Pipeline: read output i, write input i+2. */
  for (uint32_t i = 0; i < num_blocks; i++) {
    ret = poll_output_valid(base);
    if (ret) {
      return ret;
    }

    bool is_last = (i == num_blocks - 1);
    bool last_partial = is_last && (remainder != 0);

    if (last_partial) {
      aes_read_block(base, padded_out);
      memcpy(pkt->out_buf + i * 16, padded_out, remainder);
    } else {
      aes_read_block(base, pkt->out_buf + i * 16);
    }

    uint32_t next = i + 2;
    if (next < num_blocks) {
      bool next_is_partial = (next == num_blocks - 1) && (remainder != 0);
      if (next_is_partial) {
        memset(padded_in, 0, sizeof(padded_in));
        memcpy(padded_in, pkt->in_buf + next * 16, remainder);
        aes_write_block(base, padded_in);
      } else {
        aes_write_block(base, pkt->in_buf + next * 16);
      }
    }
  }

  return 0;
}

/* ------------------------------------------------------ */
/* Session Management */
/* ------------------------------------------------------ */

#define OPENTITAN_AES_LOCK_TIMEOUT K_MSEC(100)

static int opentitan_aes_begin_session(
    const struct device *dev,
    struct cipher_ctx *ctx, /* holds the session state + mode parameters (like
                               IV pointer for CBC) */
    enum cipher_algo algo,  /* zephyr API enum for algorithm (aes only:
                               CRYPTO_CIPHER_ALGO_AES) */
    enum cipher_mode mode,  /* zephyr API enum for mode (ecb, cbc, ctr:
                               CRYPTO_CIPHER_MODE_ECB) */
    enum cipher_op
        op_type) /* zephyr API enum for operation type (encrypt/decrypt:
                    CRYPTO_CIPHER_OP_ENCRYPT/CRYPTO_CIPHER_OP_DECRYPT) */
{

  /* Only AES is supported */
  if (algo != CRYPTO_CIPHER_ALGO_AES) { /* in case a buggy app tried to call
                                           begin_session with a different
                                           algorithm, we want to catch it and
                                           return a clear error message. */
    LOG_ERR("Unsupported algorithm %d; only AES is supported", algo);
    return -ENOTSUP;
  }

  /* Supported modes: ECB, CBC, CTR. */
  if (mode != CRYPTO_CIPHER_MODE_ECB && mode != CRYPTO_CIPHER_MODE_CBC &&
      mode != CRYPTO_CIPHER_MODE_CTR) {
    LOG_ERR("Unsupported mode %d; only ECB is supported in v1", mode);
    return -ENOTSUP;
  }

  /* ctx->key.bit_stream: pointer to the first byte of the key. */
  if (ctx->key.bit_stream == NULL) {
    LOG_ERR("Key pointer (ctx->key.bit_stream) is NULL"); /* in case an app
                                                             forgot to set
                                                             ctx.key.bit_stream
                                                             = his-key */
    return -EINVAL;
  }

  /* ctx->keylen is in bytes (Zephyr convention). */
  /* Convert to bits for comparison against the hardware-defined key size
   * constants. */
  uint32_t key_len_bits = (uint32_t)ctx->keylen * 8u;

  uint32_t reg_ctrl_key_len; /* we want to shift it to the correct position in
                                the control reg down below */
  uint32_t key_words_count;  /* number of 32-bit key words (4 or 8) */

  if (key_len_bits == 128u) {
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    reg_ctrl_key_len = 1u << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;
#else
    reg_ctrl_key_len =
        AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_128
        << AES_CTRL_SHADOWED_KEY_LEN_OFFSET; /* 1<<8 = 0x100 (1’b001 shifted to
                                                bits [11:8]) */
#endif
    key_words_count = 4u; /* aes_write_key() uses this to decide how many SHARE0
                             slots receive */
  } else if (key_len_bits == 256u) {
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    reg_ctrl_key_len = 2u << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;
#else
    reg_ctrl_key_len =
        AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256
        << AES_CTRL_SHADOWED_KEY_LEN_OFFSET; /* 4<<8 = 0x400 (3’b100 shifted to
                                                bits [11:8]) */
#endif
    key_words_count = 8u;

  } else {
    LOG_ERR("Unsupported key length %u bits; only 128 and 256 are supported",
            key_len_bits);
    return -EINVAL;
  }

  /* Claim a session slot (mutex-protected) */
  struct opentitan_aes_data *data = dev->data; /* dev->data->lock */

  /* This routine locks mutex. If the mutex is locked by another thread, the
   * calling thread waits until the mutex becomes available or until a timeout
   * occurs. */
  int lock_ret = k_mutex_lock(
      &data->lock,
      OPENTITAN_AES_LOCK_TIMEOUT); /* it will return 0 on success */
  // REF:
  // https://docs.zephyrproject.org/latest/doxygen/html/group__mutex__apis.html#ga850549358645249c285669baa49c33b0

  if (lock_ret != 0) {
    LOG_ERR("Could not acquire session-pool mutex (timeout)");
    return -EBUSY;
  }

  struct opentitan_aes_session *sess =
      NULL; /* intialize a pointer to the session struct, we will set it to
               point to the claimed session slot in the pool below */

  /* look for the unused session slot(free slot) and make sess pointer point to
   * it! */
  for (int i = 0; i < CONFIG_CRYPTO_OPENTITAN_MAX_SESSION; i++) {
    if (!data->sessions[i].in_use) {
      sess = &data->sessions[i];
      break;
    }
  }

  /* if all session slots are in use, return an error. The app (caller) can then
   * decide to wait and retry, or give up. */
  if (sess == NULL) {
    k_mutex_unlock(&data->lock); /* unlock the mutex before returning, otherwise
                                    we would have a deadlock */
    LOG_ERR("No free AES session slots (max = %d)",
            CONFIG_CRYPTO_OPENTITAN_MAX_SESSION);
    return -ENOMEM;
  }

  /* Now we have created a session */
  /* we have to populate this session with the needed info */
  sess->dev = dev;     /* ecb_op() needs dev->config->base_addr */
  sess->dir = op_type; /* CRYPTO_CIPHER_OP_ENCRYPT=1, _DECRYPT=0. Will be mapped
                          to HW values. */
  sess->reg_ctrl_key_len = reg_ctrl_key_len; /* pre-shifted above for direct use
                                                in the control register. */
  sess->key_words_count = key_words_count;   /* 4 or 8; */

  /* NOw we need to copy the *key* data from the caller's app to our session
   * struct! */
  for (uint32_t i = 0; i < key_words_count; i++) {
    sess->key_words[i] = sys_get_le32(ctx->key.bit_stream + i * 4u);
  }

  sess->in_use =
      true; /* means the session slot is now claimed and occupied by a session,
               so other threads can't claim it until it's freed. */

  /* now after we filled all the session info, we unlock (release) the mutex! */
  /* so other threads can claim other session slots or free this slot if they
   * want to. */
  k_mutex_unlock(&data->lock);

  /* The Zephyr crypto calls cipher_block_op(ctx, pkt), which internally does
   * ctx->ops.block_crypt_hndlr(ctx, pkt). */
  /* If it is left NULL, every encrypt/decrypt call could silently fail */
  if (mode == CRYPTO_CIPHER_MODE_ECB) {
    ctx->ops.block_crypt_hndlr = opentitan_aes_ecb_op;
    LOG_INF("AES session started: mode=ECB dir=%d key=%u bits", op_type,
            key_len_bits);
  } else if (mode == CRYPTO_CIPHER_MODE_CBC) {
    ctx->ops.cbc_crypt_hndlr = opentitan_aes_cbc_op;
    LOG_INF("AES session started: mode=CBC dir=%d key=%u bits", op_type,
            key_len_bits);
  } else { /* CTR */
    ctx->ops.ctr_crypt_hndlr = opentitan_aes_ctr_op;
    LOG_INF("AES session started: mode=CTR key=%u bits", key_len_bits);
  }

  ctx->drv_sessn_state =
      sess; /* this is how we link the session state to the ctx, so that the
               ecb_op() can retrieve it later when it needs to access the
               session info like the key and direction. */
  // REF:
  // https://docs.zephyrproject.org/latest/doxygen/html/structcipher__ctx.html#a624cf985cf35b3aa8681c3892fd67429

  uint32_t op_hw = (op_type == CRYPTO_CIPHER_OP_ENCRYPT)
                       ? AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC
                       : AES_CTRL_SHADOWED_OPERATION_VALUE_AES_DEC;
  LOG_DBG("BEGIN_SESSION CTRL_MASK = 0x%08x", sess->reg_ctrl_key_len | op_hw);

  return 0;
}

/*
 * Tears down a session created by opentitan_aes_begin_session().
 * Zeroes all key material in the session struct before releasing the slot.
 */
static int opentitan_aes_free_session(const struct device *dev,
                                      struct cipher_ctx *ctx) {

  /* NULL ctx   : caller is freeing something never received or already freed
   * (bug in the caller). */
  /* NULL sessn : begin_session() never completed; nothing to release. */
  if (ctx == NULL || ctx->drv_sessn_state == NULL) {
    LOG_ERR("free_session called with NULL ctx or drv_sessn_state");
    return -EINVAL;
  }

  struct opentitan_aes_session *sess =
      (struct opentitan_aes_session *)ctx->drv_sessn_state;
  struct opentitan_aes_data *data = dev->data;
  const struct opentitan_aes_config *cfg = dev->config;

  /* We lock the mutex to safely modify the session slot and prevent race
   * conditions with other threads that might be trying to claim or free
   * sessions at the same time. */
  int lock_ret = k_mutex_lock(&data->lock, OPENTITAN_AES_LOCK_TIMEOUT);

  if (lock_ret != 0) {
    LOG_ERR("Could not acquire session-pool mutex in free_session (timeout)");
    return -EBUSY;
  }

  /* this memset does a few things at once: */
  /* it sets in_use to false, which marks the session slot as free and available
   * for other threads to claim; */
  /* it also zeroes out key_words[], dir, dev. to prevent any potential leakage
   * of sensitive data. */
  memset(sess, 0, sizeof(struct opentitan_aes_session));

  /*
   * Flush hardware key registers.
   * OpenTitan AES holds key material in KEY_SHARE0/SHARE1 registers until
   * explicitly cleared. Without this flush, a subsequent session could
   * potentially observe residual key state via timing side-channels. See:
   * https://github.com/lowRISC/opentitan/issues/2382
   */
  opentitan_aes_hw_flush(
      cfg->base_addr); /* Scrubs KEY_SHARE0/SHARE1 hardware registers -- memset
                          above only clears SRAM. */

  /* After zeroing the session struct, we can safely release the mutex, allowing
   * other threads to claim this now-free session slot or free other slots. */
  k_mutex_unlock(&data->lock);

  /* NULL-ing drv_sessn_state after the mutex is released is safe because */
  /* ctx is owned by the calling thread (not shared via data->sessions). */
  /* so we need to break the link between the ctx and the session struct */
  /* to prevent any accidental access to a freed session in future calls. */
  ctx->drv_sessn_state = NULL;

  LOG_INF("AES session freed");

  return 0;
}

#define OPENTITAN_AES_HW_CAPS                                                  \
  (CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS)
// REF:
// https://github.com/zephyrproject-rtos/zephyr/blob/9a51ed649e8a9dfc6c15b802f9d6c7236450f0b5/include/zephyr/crypto/crypto.h#L175-L192

static int opentitan_aes_query_hw_caps(const struct device *dev) {
  ARG_UNUSED(dev);
  return OPENTITAN_AES_HW_CAPS;
}

static DEVICE_API(crypto, opentitan_aes_api) = {
    .query_hw_caps = opentitan_aes_query_hw_caps,
    .cipher_begin_session = opentitan_aes_begin_session,
    .cipher_free_session = opentitan_aes_free_session,
};

#define OPENTITAN_AES_INIT(n)                                                  \
                                                                               \
  static const struct opentitan_aes_config opentitan_aes_cfg_##n = {           \
      .base_addr = DT_INST_REG_ADDR(n),                                        \
  };                                                                           \
                                                                               \
  static struct opentitan_aes_data opentitan_aes_data_##n = {                  \
      .lock = Z_MUTEX_INITIALIZER(opentitan_aes_data_##n.lock),                \
  };                                                                           \
                                                                               \
  DEVICE_DT_INST_DEFINE(n, opentitan_aes_init, NULL, &opentitan_aes_data_##n,  \
                        &opentitan_aes_cfg_##n, POST_KERNEL,                   \
                        CONFIG_CRYPTO_INIT_PRIORITY, &opentitan_aes_api);

DT_INST_FOREACH_STATUS_OKAY(OPENTITAN_AES_INIT)
