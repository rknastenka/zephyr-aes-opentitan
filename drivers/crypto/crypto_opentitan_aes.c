// ------------------------------------------------------
// 1. Device Tree Compatibility
// ------------------------------------------------------

#define DT_DRV_COMPAT lowrisc_opentitan_aes

// ------------------------------------------------------
// 2. Header Includes
// ------------------------------------------------------

#include <stdint.h>                 // For fixed-width integer types (uint32_t)
#include <errno.h>                  // For error codes (-EINVAL, -ENOTSUP) returned by Zephyr APIs.
#include <string.h>                 // For memset() and memcpy() used in buffer and key manipulations.

#include <zephyr/kernel.h>          // the k_mutex used in our data struct for thread safety.
#include <zephyr/irq.h>             // For irq_lock() / irq_unlock()
#include <zephyr/device.h>          // DEVICE_DT_INST_DEFINE macro to register the driver instance with the OS.
#include <zephyr/devicetree.h>      // For parsing the .dts files (e.g., DT_INST_REG_ADDR) to get hardware memory addresses.
#include <zephyr/sys/sys_io.h>      // For sys_read32() and sys_write32() to read/write to the memory-mapped registers.
#include <zephyr/sys/byteorder.h>   // To handle endianness when loading keys/data into the AES block.
#include <zephyr/crypto/crypto.h>   // (crypto_session, crypto_pkt).
#include <zephyr/crypto/cipher.h>   // (CRYPTO_CIPHER_MODE_CBC, CRYPTO_CIPHER_ALGO_AES).
#include <zephyr/logging/log.h>      // For the LOG_ERR(), LOG_INF(): Debugging

LOG_MODULE_REGISTER(opentitan_aes, CONFIG_CRYPTO_LOG_LEVEL);

// ------------------------------------------------------
// 3. Register Offsets and Bitmasks (macro)
// ------------------------------------------------------

// Base Offsets for Registers (Keys, IV, Data)
#define AES_KEY_SHARE0_0_REG_OFFSET 0x4
#define AES_KEY_SHARE1_0_REG_OFFSET 0x24
#define AES_IV_0_REG_OFFSET 0x44
#define AES_DATA_IN_0_REG_OFFSET 0x54
#define AES_DATA_OUT_0_REG_OFFSET 0x64

// Control Register & Bitmasks
#define AES_CTRL_SHADOWED_REG_OFFSET 0x74
#define AES_CTRL_SHADOWED_OPERATION_OFFSET 0
#define AES_CTRL_SHADOWED_OPERATION_VALUE_AES_ENC 0x1
#define AES_CTRL_SHADOWED_OPERATION_VALUE_AES_DEC 0x2

#define AES_CTRL_SHADOWED_MODE_OFFSET 2
#define AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB 0x1
#define AES_CTRL_SHADOWED_MODE_VALUE_AES_CBC 0x2

#define AES_CTRL_SHADOWED_KEY_LEN_OFFSET 8
#define AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_128 0x1
#define AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256 0x4 // will not support AES-192 in v1, 128 and 256 are enough for now, 192-bit keys are not commonly used in practice.

#define AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT 15

// Trigger Register
#define AES_TRIGGER_REG_OFFSET 0x80
#define AES_TRIGGER_START_BIT 0
#define AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT    1
#define AES_TRIGGER_DATA_OUT_CLEAR_BIT          2

// Status Register
#define AES_STATUS_REG_OFFSET 0x84
#define AES_STATUS_IDLE_BIT 0
#define AES_STATUS_OUTPUT_VALID_BIT 3
#define AES_STATUS_INPUT_READY_BIT 4

// The rest of the definitions in aes_regs.h cover advanced features 
// that fall outside the standard Zephyr OS Crypto API (<zephyr/crypto.h>). 
// like: Fault-Injection/PRNGs/GCM
// Including them now just adds dead code.

// ------------------------------------------------------
// 4. Configuration Structure
// ------------------------------------------------------

struct opentitan_aes_config {
    mm_reg_t base_addr;
};

struct opentitan_aes_session {
    bool in_use;
    const struct device *dev;   // Added so we can retrieve 'dev' inside the processing loop
    enum cipher_op dir;         // operation: encrypt/decrypt (CRYPTO_CIPHER_OP_DECRYPT/CRYPTO_CIPHER_OP_ENCRYPT)
// in zephyr APIs, 1=enc, 2=dec.
// which is the same as in the opentitan CTRL Reg space for (0x1 for enc, 0x2 for dec)
// placed in bit 0 and bit 1 so we don't need to do any mapping or shifting
// that's why we can use the cipher_op (zephyr API) enum 
// directly in the session struct, instead of defining our own enum for enc/dec.


// on the contrast here, zephyer API defines the cipher modes as bitmasks (1 for ECB, 2 for CBC),
// but in the opentitan hardware, the mode (ECB/CBC) is not a bitmask, 
// but rather a value that sits in bits 2-7 of the control register
// that is why we can't use the zephyr API enum for cipher modes directly in the session struct,
// and instead we need to define our own enum or just use a uint32_t for the mode
// if we wrote: enum cipher_mode mode here, we would have to do a mapping from the zephyr API enum values (1 for ECB, 2 for CBC)
// to the opentitan hardware values every time we set up the control register for an operation, 
// which adds unnecessary complexity and overhead
// which we have to okay use enum but then shift the valuse to the 2-7 bits space each time the computert encrypts/decrypts a block.
    uint32_t reg_ctrl_key_len;  // key length: 128/256 -- pre-shifted to bits [11:8] of CTRL
    uint32_t key_words_count;   // 4 = AES-128, 8 = AES-256 
    uint32_t key_words[8];      // register to store the key (8 words * 32bits = 256-bit max key)  
};

// #define OPENTITAN_AES_MAX_SESSIONS 2

// Mutex and Semaphore for Thread Safety and Synchronization 
// prevent race conditions when multiple threads access the same AES hardware
struct opentitan_aes_data {
    struct k_mutex lock;  // Prevents concurrent aes access across threads
    // struct k_sem aes_done;     // A Semaphore to signal when hardware is done (interrupt)
    // However, since we are doing polling in this driver, we don't need the semaphore
    // it's a design choice by opentitan AES, it doesn't have an interrupt line to signal when the operation is done,
    // so we have to poll the status register to check when the operation is complete.
    // but we still need the mutex to prevent multiple threads from accessing the hardware at the same
    
    // A pool of sessions assigned to different Zephyr threads
    // struct opentitan_aes_session sessions[OPENTITAN_AES_MAX_SESSIONS];
    struct opentitan_aes_session sessions[CONFIG_CRYPTO_OPENTITAN_MAX_SESSION];
};

// ------------------------------------------------------
// 5. Initialization and Reset
// ------------------------------------------------------

// Replace all the polling function with one helper in v2
// static int poll_idle(mm_reg_t base)
// {
//     uint32_t t = 0;
//     while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1u << AES_STATUS_IDLE_BIT))) {
//         if (t++ > (AES_TIMEOUT_US / 10)) {
//             return -ETIMEDOUT;
//         }
//         k_busy_wait(10);
//     }
//     return 0;
// }


#define AES_TIMEOUT_US                      10000  // 10ms timeout for hardware to respond


/*
 * Hardware-level flush.
 * Clears keys, IVs, and data registers and returns hardware to IDLE.
 *
 * Called at boot and during session teardown to prevent key leakage.
 */
static int opentitan_aes_hw_flush(mm_reg_t base)
{
    uint32_t timeout = 0;


/* explainging the WHILE loop:                         */
//    Keep reading the STATUS register.
//   Check if bit 0 is 1 (hardware idle).
//   If yes → stop waiting, get out of the loop.
//   If no  → wait 10 microseconds, try again.
//   If we've tried 1000 times → give up, return an error.


    // Wait for IDLE before touching Control Register
    // Writes to Control Register are silently ignored if hardware is not idle
    while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1 << AES_STATUS_IDLE_BIT))) {
        if (timeout++ > (AES_TIMEOUT_US / 10)) {
            return -ETIMEDOUT;
        }
        k_busy_wait(10);
    }
    timeout = 0;

    // Set MANUAL_OPERATION=1 to disable autostart the enc/dec
    // (noted in opentitan AES HW docs to be required for a successful flush)
    // Double-write required for all shadowed registers
    uint32_t ctrl_val = (1u << AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT); // 1 << 15
    sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
    sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
    // we will set the MANUAL_OPERATION back to zero in the begin_session()
    // because we want the autostart feature for normal encryption/decryption operations
    // we only need to disable it for the flush operation at boot and during session teardown.


    // Re-poll IDLE bcz control register write may trigger an internal PRNG reseed
    while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1 << AES_STATUS_IDLE_BIT))) {
        if (timeout++ > (AES_TIMEOUT_US / 10)) {
            return -ETIMEDOUT;
        }
        k_busy_wait(10);
    }
    timeout = 0;


    // Trigger hardware clear of keys, IVs, and all data registers
    sys_write32((1 << AES_TRIGGER_KEY_IV_DATA_IN_CLEAR_BIT) |
                (1 << AES_TRIGGER_DATA_OUT_CLEAR_BIT),
                base + AES_TRIGGER_REG_OFFSET);

     
                
    // Wait for IDLE after clear completes
    // The hardware clear takes several clock cycles to overwrite all registers with PRNG-generated data.
    while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1 << AES_STATUS_IDLE_BIT))) {
        if (timeout++ > (AES_TIMEOUT_US / 10)) {
            return -ETIMEDOUT;
        }
        k_busy_wait(10);
    }


    return 0;
}


/*
 * Zephyr device initialization callback
 */
static int opentitan_aes_init(const struct device *dev)
{
    struct opentitan_aes_data *data = dev->data;
    const struct opentitan_aes_config *cfg = dev->config;

    k_mutex_init(&data->lock);

    // Clear all software session slots
    for (int i = 0; i < CONFIG_CRYPTO_OPENTITAN_MAX_SESSION; i++) {
        data->sessions[i].in_use = false;
        memset(data->sessions[i].key_words, 0, sizeof(data->sessions[i].key_words));
    }

    // Flush hardware state at boot
    int ret = opentitan_aes_hw_flush(cfg->base_addr);
    if (ret != 0) {
        LOG_ERR("OpenTitan AES hardware flush failed (timed out)");
        return ret;
    }

    LOG_INF("OpenTitan AES driver initialized.");
    return 0;
}


// ------------------------------------------------------
// 6. Read and Write Functions & Helpers
// ------------------------------------------------------

 // final key is done by XORing SHARE0 and SHARE1
 // effective_key = SHARE0 XOR SHARE1
    static void aes_write_key(mm_reg_t base,
                             const uint32_t *key_words,  // word=32bits // AES-128 gives 4 words, AES-256 gives 8
                             uint32_t key_word_count)    // How many of those words above are real key material (4 or 8), rest is padding
    {
        // share0-share7
        for (int i = 0; i < 8; i++) {                                             // The loop always runs 8 times, all 8 register slots must be written
            uint32_t share0_word = (i < (int)key_word_count) ? key_words[i] : 0u; // if i is less than the actual key word count, write the real key word; otherwise write zero for padding
            if (i < (int)key_word_count) {
                LOG_DBG("KEY_SHARE0_%d = 0x%08x", i, share0_word);
            }
            sys_write32(share0_word, base + AES_KEY_SHARE0_0_REG_OFFSET + i * 4); // jump 4bytes to go to the next SHARE0_i register
        }

        // SHARE1 is always zero in v1 (no side-channel masking).
        // If we later add support for masked keys, this loop can be modified to write the actual share1 words instead of zeros.
        for (int i = 0; i < 8; i++) {
            sys_write32(0u, base + AES_KEY_SHARE1_0_REG_OFFSET + i * 4);
        }
    }

// this will be used in v2
static void aes_write_iv(mm_reg_t base, 
                        const uint32_t *iv_words) //IV is always 128 bits, so it's always 4 words(IV_0..IV_3), no need for a word count parameter
{
    for (int i = 0; i < 4; i++) {
        sys_write32(iv_words[i], base + AES_IV_0_REG_OFFSET + i * 4); // IV_0..IV_3
    }
}
/*
 * Called only for CBC mode; ECB has no IV. 
 *
 * After each CBC block the hardware automatically updates IV_0..IV_3
 * to the last ciphertext block, so software does NOT need to re-write
 * the IV between blocks of the same message — only for a new message.
 *
 *   IV source on decryption:
 *   AES-CBC decryption requires the *original* IV for the first block.
 *   The Zephyr API passes ctx->mode_params.cbc_info.iv for this.
 *   Make sure cbc_op() passes the user-supplied IV here and NOT a
 *   stale value from a previous encrypt call stored in the session.
 */


static void aes_write_block(mm_reg_t base,
                            const uint8_t *src) // Pointer to the 16-byte input block 
// src is uint8_t, not uint32_t like the key and IV. 
// That's because the Zephyr crypto API gives you a raw byte buffer (pkt->in_buf), 
// not a pre-chunked word array. 
{
    for (int i = 0; i < 4; i++) {
        uint32_t word = sys_get_le32(src + i * 4);
        LOG_DBG("DATA_IN_%d = 0x%08x", i, word);
        sys_write32(word, base + AES_DATA_IN_0_REG_OFFSET + i * 4);
    }
}

//  * Why sys_get_le32() instead of a cast to uint32_t *?
// It reads 4 bytes starting at src + i*4 and assembles them into a uint32_t in little-endian order. It solves two problems at once:
/*
  Problem 1 — Alignment. pkt->in_buf is a uint8_t *. 
  If you tried to cast it directly to uint32_t * and read it,
  you might crash on hardware that requires 4-byte aligned reads. 
  sys_get_le32 reads byte-by-byte internally so alignment doesn't matter.
*/
/*
Problem 2 — Endianness. The AES DATA_IN registers expect little-endian words. 
sys_get_le32 guarantees that byte 0 of your input ends up in bits 0–7 of the word, 
byte 1 in bits 8–15, and so on. regardless of whether the CPU is big or little endian.
*/




static void aes_read_block(mm_reg_t base, uint8_t *dst)
{
    for (int i = 0; i < 4; i++) {
        uint32_t word = sys_read32(base + AES_DATA_OUT_0_REG_OFFSET + i * 4);
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
 *
 */


// ------------------------------------------------------
// 7. AES Modes - ECB only for v1, CBC in v2
// ------------------------------------------------------

// static int opentitan_aes_ecb_op
// static int opentitan_aes_cbc_op


/*
 * loop until STATUS.INPUT_READY (bit 4) is set, meaning the hardware
 * has consumed the previous DATA_IN write and is ready for a new block.
 *
 * Returns 0 on success, -ETIMEDOUT if the hardware does not respond
 * within AES_TIMEOUT_US microseconds.
 */
static int poll_input_ready(mm_reg_t base)
{
	uint32_t t = 0;

	while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1u << AES_STATUS_INPUT_READY_BIT))) {
		if (t++ > (AES_TIMEOUT_US / 10)) {
			return -ETIMEDOUT;
		}
		k_busy_wait(10);
	}
	return 0;
}


/*
 * loop until STATUS.OUTPUT_VALID (bit 3) is set, meaning the hardware
 * has finished processing a block and the result is ready in DATA_OUT.
 *
 * Returns 0 on success, -ETIMEDOUT if the hardware does not respond
 * within AES_TIMEOUT_US microseconds.
 */
static int poll_output_valid(mm_reg_t base)
{
	uint32_t t = 0;

	while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1u << AES_STATUS_OUTPUT_VALID_BIT))) {
		if (t++ > (AES_TIMEOUT_US / 10)) {
			return -ETIMEDOUT;
		}
		k_busy_wait(10);
	}
	return 0;
}


// ECB mode:
// Process the input data in 16-byte blocks
// writing each block to the AES_DATA_IN registers
// and reading the result from AES_DATA_OUT after each block is processed.
static int opentitan_aes_ecb_op(struct cipher_ctx *ctx, struct cipher_pkt *pkt) // these are zephyr API structs
//                                                                              // cipher_ctx has the session pointer and mode parameters (like IV pointer for CBC)
{                                                                               // cipher_pkt has the input and output buffers and lengths
//                                                                              // REF: https://docs.zephyrproject.org/latest/doxygen/html/structcipher__ctx.html
	const struct opentitan_aes_session *sess = (const struct opentitan_aes_session *)ctx->drv_sessn_state; //sess is a pointer to a pointer to know this exact session state(dir, key, key_len)
	const struct opentitan_aes_config *cfg =   (const struct opentitan_aes_config *)sess->dev->config;
	mm_reg_t base = cfg->base_addr;
	
    uint32_t t = 0;

	 // ECB has no padding in v1 - caller must supply one or more complete 16-byte blocks.
	if (pkt->in_len == 0 || (pkt->in_len % 16) != 0) { // in_len: Number of input **bytes** to process. // it must be non zero and a multiple of 16 
		return -EINVAL;//Invalid Argument              
	}

	uint32_t num_blocks = pkt->in_len / 16; // number of 16-byte(128bits) blocks to process, used for loop control below


	// We set up the control register once at the start of the operation, and the hardware remains configured for the entire message.
    // The OPERATION, MODE, and KEY_LEN
    uint32_t ctrl_val =
                ((uint32_t)sess->dir << AES_CTRL_SHADOWED_OPERATION_OFFSET)            |  // OPERATION
                (AES_CTRL_SHADOWED_MODE_VALUE_AES_ECB << AES_CTRL_SHADOWED_MODE_OFFSET) | // MODE
                sess->reg_ctrl_key_len; // pre-shifted to bits [11:8] by begin_session    // KEY_LEN
    LOG_DBG("CTRL_SHADOWED = 0x%08x", ctrl_val);

    /*
	 * Bit layout:
	 *   [1:0]  OPERATION  — (uint32_t)sess->dir : (1=enc, 2=dec; matches hardware directly)
	 *   [7:2]  MODE       — AES_ECB shifted to bits [7:2]
	 *   [11:8] KEY_LEN    — sess->reg_ctrl_key_len (pre-shifted by begin_session)
	 *   [15]   MANUAL_OP  — 0 (autostart enabled)
	 */


    // Wait for IDLE before touching Control Register
    // Writes to Control Register are silently ignored if hardware is not idle
    while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1u << AES_STATUS_IDLE_BIT))) {
        if (t++ > (AES_TIMEOUT_US / 10)) { return -ETIMEDOUT; }
        k_busy_wait(10);
    }

	sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET);
	sys_write32(ctrl_val, base + AES_CTRL_SHADOWED_REG_OFFSET); // shadowed


	 // Wait for IDLE after writing CTRL.
	 // A CTRL write may trigger an internal PRNG reseed.
     // Key writes issued before IDLE is set are silently ignored.
	while (!(sys_read32(base + AES_STATUS_REG_OFFSET) & (1u << AES_STATUS_IDLE_BIT))) {
		if (t++ > (AES_TIMEOUT_US / 10)) {
			return -ETIMEDOUT;
		}
		k_busy_wait(10);
	}
/*
* Opentitan Reference: Since writing this register may initiate the reseeding of the internal PRNGs,
*                     software must check that the AES unit is idle before providing the initial key.
*/

    // Write the key after confirming the hardware is ready to accept it.
	aes_write_key(base, sess->key_words, sess->key_words_count); // block 0 - outside the loop

    // check INPUT_READY reg before writing the first block
    int ret = poll_input_ready(base);
	if (ret) {
		return ret;
	}


    // WRITE THE FIRST BLOCK TO START THE ENCRYPTION/DECRYPTION
	aes_write_block(base, pkt->in_buf); /* block 0 — hardware auto-starts */
// this is the first block, we write it before the loop, 
// because after writing the first block, 
// the hardware starts processing and 
// we can start ***polling for the output of the first block while writing the second block****, 
// which is more efficient than waiting for the first block to finish before writing the second block.


 // How the pipline works in ECB mode:

// in every iteration:
// READ *block0* --- WRITE *blcok1*
// READ *block1* --- WRITE *block2*

// REF OpenTitan: "While the AES unit is performing encryption/decryption, the processor can safely write the next input data block into the CSRs."

	for (uint32_t i = 0; i < num_blocks; i++) {

		// Wait for block i to complete the encryption/decryption and the result to be ready in DATA_OUT before reading it.
		ret = poll_output_valid(base);
		if (ret) {
			return ret;
		}

		
        // READ THE ENCRYPTED/DECRYPTED block
		aes_read_block(base, pkt->out_buf + i * 16);     // Read all *four* DATA_OUT words(16bytes), must to release interlock so it can accept the next block.

        // SEND A NEW BLOCK TO BE ENCRYPTED/DECRYPTED
		if (i < num_blocks - 1) {
			aes_write_block(base, pkt->in_buf + (i + 1) * 16); // this means read the first 
            // in_buf is just a (1byte) pointer, it points to the first byte of the input message, and we are treating it as an array of bytes.
		}
        // we write the next input block direclty after reading the output: No poll_input_ready() needed -- note down below.

	}
    // out_buf: [ encrypted block 0 ][ encrypted block 1 ] ...

	return 0;
}
/*
 * Note: OpenTitan programmer's guide: INPUT_READY is guaranteed to be 1
 * when OUTPUT_VALID is 1. After  poll_output_valid() + aes_read_block(),
 * the next aes_write_block() needs no extra poll_input_ready() call

there's indeed a one cycle gap here, but we're writing software, we don't care much about it
*/



// ------------------------------------------------------
// 8. Session Management
// ------------------------------------------------------


//Mutex timeout for begin_session / free_session.
#define OPENTITAN_AES_LOCK_TIMEOUT  K_MSEC(100)

/*
 * ctx->drv_sessn_state is set to the claimed slot so that ecb_op() can
 * retrieve it as:
 *   const struct opentitan_aes_session *sess = (const struct opentitan_aes_session *)ctx->drv_sessn_state;
 
 * v1 scope: ECB only.  All other modes return -ENOTSUP immediately.
 */

 /*
 * Returns 0 on success, or:
 *   -ENOTSUP  algo is not AES, or mode is not ECB
 *   -EINVAL   key length is not 128 or 256 bits, or key pointer is NULL
 *   -ENOMEM   all CONFIG_CRYPTO_OPENTITAN_MAX_SESSION slots are busy
 *   -EBUSY    could not acquire the session-pool mutex within the timeout
 */

 
static int opentitan_aes_begin_session(const struct device *dev,
                                        struct cipher_ctx   *ctx,      // holds the session state + mode parameters (like IV pointer for CBC)
                                        enum cipher_algo     algo,     // zephyr API enum for algorithm (aes only:  CRYPTO_CIPHER_ALGO_AES)
                                        enum cipher_mode     mode,     // zephyr API enum for mode (ecb only:  CRYPTO_CIPHER_MODE_ECB)
                                        enum cipher_op       op_type)  // zephyr API enum for operation type (encrypt/decrypt: CRYPTO_CIPHER_OP_ENCRYPT/CRYPTO_CIPHER_OP_DECRYPT)
{

    // Only AES is supported
    if (algo != CRYPTO_CIPHER_ALGO_AES) {  // in case a buggy app tried to call begin_session with a different algorithm, we want to catch it and return a clear error message.
        LOG_ERR("Unsupported algorithm %d; only AES is supported", algo);
        return -ENOTSUP;
    }

    // Only ECB is supported 
    if (mode != CRYPTO_CIPHER_MODE_ECB) {
        LOG_ERR("Unsupported mode %d; only ECB is supported in v1", mode);
        return -ENOTSUP;
    }


    // ctx->key.bit_stream: pointer to the first byte of the key.
    if (ctx->key.bit_stream == NULL) {
        LOG_ERR("Key pointer (ctx->key.bit_stream) is NULL"); // in case an app forgot to set ctx.key.bit_stream = his-key
        return -EINVAL;
    }


    // ctx->keylen is in bytes (Zephyr convention).
    // Convert to bits for comparison against the hardware-defined key size constants.
    uint32_t key_len_bits = (uint32_t)ctx->keylen * 8u;

    uint32_t reg_ctrl_key_len;  // we want to shift it to the correct position in the control reg down below
    uint32_t key_words_count;   // number of 32-bit key words (4 or 8)

    if (key_len_bits == 128u) {
    #if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
        reg_ctrl_key_len = 1u << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;
    #else
        reg_ctrl_key_len = AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_128 << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;  // 1<<8 = 0x100 (1’b001 shifted to bits [11:8])
    #endif
        key_words_count = 4u; //aes_write_key() uses this to decide how many SHARE0 slots receive

    } else if (key_len_bits == 256u) {
    #if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
        reg_ctrl_key_len = 2u << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;
    #else
        reg_ctrl_key_len = AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256 << AES_CTRL_SHADOWED_KEY_LEN_OFFSET;  // 4<<8 = 0x400 (3’b100 shifted to bits [11:8])
    #endif
        key_words_count  = 8u;

    } else {
        LOG_ERR("Unsupported key length %u bits; only 128 and 256 are supported", key_len_bits);
        return -EINVAL;
    }


    // Claim a session slot (mutex-protected)
    struct opentitan_aes_data *data = dev->data; // dev->data->lock

    // This routine locks mutex. If the mutex is locked by another thread, the calling thread waits until the mutex becomes available or until a timeout occurs.
    int lock_ret = k_mutex_lock(&data->lock, OPENTITAN_AES_LOCK_TIMEOUT); // it will return 0 on success 
    //REF: https://docs.zephyrproject.org/latest/doxygen/html/group__mutex__apis.html#ga850549358645249c285669baa49c33b0

    if (lock_ret != 0) {
        LOG_ERR("Could not acquire session-pool mutex (timeout)");
        return -EBUSY;
    }

    struct opentitan_aes_session *sess = NULL; // intialize a pointer to the session struct, we will set it to point to the claimed session slot in the pool below

    // look for the unused session slot(free slot) and make sess pointer point to it!
    for (int i = 0; i < CONFIG_CRYPTO_OPENTITAN_MAX_SESSION; i++) {
        if (!data->sessions[i].in_use) {
            sess = &data->sessions[i];
            break;
        }
    }

    // if all session slots are in use, return an error. The app (caller) can then decide to wait and retry, or give up.
    if (sess == NULL) {
        k_mutex_unlock(&data->lock); // unlock the mutex before returning, otherwise we would have a deadlock
        LOG_ERR("No free AES session slots (max = %d)", CONFIG_CRYPTO_OPENTITAN_MAX_SESSION);
        return -ENOMEM;
    }

// Now we have created a session!
// we have to populate this session with the needed info
    sess->dev  = dev;      // ecb_op() needs dev->config->base_addr  
    sess->dir  = op_type;  // CRYPTO_CIPHER_OP_ENCRYPT=1, _DECRYPT=2. Matches OpenTitan CTRL-OPERATION field directly — no remapping needed. 
    sess->reg_ctrl_key_len = reg_ctrl_key_len;  // pre-shifted above for direct use in the control register.
    sess->key_words_count  = key_words_count;   // 4 or 8;

    // NOw we need to copy the *key* data from the caller's app to our session struct!
    for (uint32_t i = 0; i < key_words_count; i++) {
        sess->key_words[i] = sys_get_le32(ctx->key.bit_stream + i * 4u);
    }


    sess->in_use = true; // means the session slot is now claimed and occupied by a session, so other threads can't claim it until it's freed.

    // now after we filled all the session info, we unlock (release) the mutex!
    // so other threads can claim other session slots or free this slot if they want to.
    k_mutex_unlock(&data->lock);


    
    // The Zephyr crypto calls cipher_block_op(ctx, pkt), which internally does ctx->ops.block_crypt_hndlr(ctx, pkt).
    // If it is left NULL, every encrypt/decrypt call could silently fail
    ctx->ops.block_crypt_hndlr = opentitan_aes_ecb_op;

     // v2: for a CBC session this line becomes:
     // ctx->ops.cbc_crypt_hndlr = opentitan_aes_cbc_op;
    
    /*
    struct cipher_ops { cipher_mode mode; union {
        cipher_op_t block_crypt_hndlr;   // ECB
        cipher_op_t cbc_crypt_hndlr;     // CBC
        cipher_op_t ctr_crypt_hndlr;     // CTR
    };
    */

    ctx->drv_sessn_state = sess; // this is how we link the session state to the ctx, so that the ecb_op() can retrieve it later when it needs to access the session info like the key and direction.
    // REF: https://docs.zephyrproject.org/latest/doxygen/html/structcipher__ctx.html#a624cf985cf35b3aa8681c3892fd67429

    LOG_INF("AES session started: mode=ECB dir=%d key=%u bits", op_type, key_len_bits);

    return 0;
}


/*
 * Tears down a session created by opentitan_aes_begin_session().
 * Zeroes all key material in the session struct before releasing the slot.
 *
 * Returns 0 on success, or:
 *   -EINVAL   ctx is NULL, or ctx->drv_sessn_state is NULL
 *   -EBUSY    could not acquire the session-pool mutex within the timeout
 */
static int opentitan_aes_free_session(const struct device *dev, struct cipher_ctx   *ctx)
{

    // NULL ctx   : caller is freeing something never received or already freed (bug in the caller).
    // NULL sessn : begin_session() never completed; nothing to release.
    if (ctx == NULL || ctx->drv_sessn_state == NULL) {
        LOG_ERR("free_session called with NULL ctx or drv_sessn_state");
        return -EINVAL;
    }

    struct opentitan_aes_session *sess = (struct opentitan_aes_session *)ctx->drv_sessn_state;
    struct opentitan_aes_data *data = dev->data;
    const struct opentitan_aes_config *cfg = dev->config;


// We lock the mutex to safely modify the session slot and prevent race conditions with other threads that might be trying to claim or free sessions at the same time.
    int lock_ret = k_mutex_lock(&data->lock, OPENTITAN_AES_LOCK_TIMEOUT);

    if (lock_ret != 0) {
        LOG_ERR("Could not acquire session-pool mutex in free_session (timeout)");
        return -EBUSY;
    }

    // this memset does a few things at once: 
    // it sets in_use to false, which marks the session slot as free and available for other threads to claim;
    // it also zeroes out key_words[], dir, dev. to prevent any potential leakage of sensitive data.
    memset(sess, 0, sizeof(struct opentitan_aes_session));

/*
 * Flush hardware key registers.
 * OpenTitan AES holds key material in KEY_SHARE0/SHARE1 registers until explicitly cleared. 
 * Without this flush, a subsequent session could potentially observe residual key state via timing side-channels.
 * See: https://github.com/lowRISC/opentitan/issues/2382
 */
    opentitan_aes_hw_flush(cfg->base_addr);  // Scrubs KEY_SHARE0/SHARE1 hardware registers -- memset above only clears SRAM.


    // After zeroing the session struct, we can safely release the mutex, allowing other threads to claim this now-free session slot or free other slots.
    k_mutex_unlock(&data->lock);


    // NULL-ing drv_sessn_state after the mutex is released is safe because
    // ctx is owned by the calling thread (not shared via data->sessions). 
    // so we need to break the link between the ctx and the session struct
    // to prevent any accidental access to a freed session in future calls.
    ctx->drv_sessn_state = NULL;

    LOG_INF("AES session freed");

    return 0;
}


// ------------------------------------------------------
// 9. Hardware Capability Query
// ------------------------------------------------------

#define OPENTITAN_AES_HW_CAPS (CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS)
// REF: https://github.com/zephyrproject-rtos/zephyr/blob/9a51ed649e8a9dfc6c15b802f9d6c7236450f0b5/include/zephyr/crypto/crypto.h#L175-L192

// CAP_RAW_KEY - I load raw bytes directly
// CAP_SEPARATE_IO_BUFS - Separate buffers, ecb_op() reads from pkt->in_buf and writes to pkt->out_buf
// CAP_SYNC_OPS - *Polling* blocks until done


static int opentitan_aes_query_hw_caps(const struct device *dev)
{
    ARG_UNUSED(dev);
    return OPENTITAN_AES_HW_CAPS;
}



// ------------------------------------------------------
// 10. Hooking up the API
// ------------------------------------------------------

// The Zephyr crypto_driver_api struct ties our functions to the generic crypto API layer.
static DEVICE_API(crypto, opentitan_aes_api) = {
    .query_hw_caps             = opentitan_aes_query_hw_caps,
    .cipher_begin_session      = opentitan_aes_begin_session,
    .cipher_free_session       = opentitan_aes_free_session,
};

/*
my structs:                       Zephyr device kernal structs:                              
opentitan_aes_config  ────────── struct device .config   (step11)
opentitan_aes_data    ────────── struct device .data     (step11)
opentitan_aes_api     ────────── struct device .api      (step10) 
*/



// ------------------------------------------------------
// 11. Device Instantiation 
// ------------------------------------------------------

// It just saying there's an AES block in your SoC, and its base address is whatever the Devicetree says it is.
// for openTitan SoC they have only one AES block so n=0 always
// but if same aes was used on another SoC, that's where we need the n to create multiple instances of the driver for each AES block.


#define OPENTITAN_AES_INIT(n)                                              \
                                                                           \
    static const struct opentitan_aes_config opentitan_aes_cfg_##n = {    \
        .base_addr = DT_INST_REG_ADDR(n),                                  \
    };                                                                     \
                                                                           \
    static struct opentitan_aes_data opentitan_aes_data_##n = {           \
        .lock = Z_MUTEX_INITIALIZER(opentitan_aes_data_##n.lock),         \
    };                                                                     \
                                                                           \
    DEVICE_DT_INST_DEFINE(n,                                               \
        opentitan_aes_init,                                                \
        NULL,                                                              \
        &opentitan_aes_data_##n,                                           \
        &opentitan_aes_cfg_##n,                                            \
        POST_KERNEL,                                                       \
        CONFIG_CRYPTO_INIT_PRIORITY,                                       \
        &opentitan_aes_api);

DT_INST_FOREACH_STATUS_OKAY(OPENTITAN_AES_INIT)   // Find every "lowrisc,opentitan-aes" in the Devicetree and run the macro above


/*
DEVICE_DT_INST_DEFINE(
    n,                          // instance number - names the device object
    opentitan_aes_init,         // function to call at boot (section 5)
    NULL,                       // no power management in v1
    &opentitan_aes_data_##n,    // pointer to the mutable data struct
    &opentitan_aes_cfg_##n,     // pointer to the const config struct
    POST_KERNEL,                // init level: kernel is up, but app not yet
    CONFIG_CRYPTO_INIT_PRIORITY,// numeric priority within POST_KERNEL // lower number drvier runs first
    &opentitan_aes_api          // pointer to our crypto_driver_api (section 10)
);
*/

// post kernal: means after hte kernal is up, but before the application starts.
