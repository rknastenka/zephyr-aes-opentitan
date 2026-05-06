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
            sys_write32(share0_word, base + AES_KEY_SHARE0_0_REG_OFFSET + i * 4); // jump 4bytes to go to the next SHARE0_i register
        }

        // SHARE1 is always zero in v1 (no side-channel masking).
        // If we later add support for masked keys, this loop can be modified to write the actual share1 words instead of zeros.
        for (int i = 0; i < 8; i++) {
            sys_write32(0u, base + AES_KEY_SHARE1_0_REG_OFFSET + i * 4);
        }
    }


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
//                                                                              // cipher_ctx has the session pointer and mode 
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

    /*
	 * Bit layout:
	 *   [1:0]  OPERATION  — (uint32_t)sess->dir : (1=enc, 2=dec; matches hardware directly)
	 *   [7:2]  MODE       — AES_ECB shifted to bits [7:2]
	 *   [11:8] KEY_LEN    — sess->reg_ctrl_key_len (pre-shifted by begin_session)
	 *   [15]   MANUAL_OP  — 0 (autostart enabled)
	 */

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

which aes mode was chosen


// ------------------------------------------------------
// 9. Zephyr Kernal threading functions 
// ------------------------------------------------------

Thread Safety Hooks / Locks / Polling Hooks


// ------------------------------------------------------
// 10. Hooking up the API
// ------------------------------------------------------

static DEVICE_API( ) = {

};


------------------------------------------------------
// 11. Device Instantiation 
// ------------------------------------------------------

// It just saying there's an AES block in your SoC, and its base address is whatever the Devicetree says it is.
// for openTitan SoC they have only one AES block so n=0 always
// but if same aes was used on another SoC, that's where we need the n to create multiple instances of the driver for each AES block.


DT_INST_FOREACH_STATUS_OKAY(OPENTITAN_AES_INIT)

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
