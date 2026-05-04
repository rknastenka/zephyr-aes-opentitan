------------------------------------------------------
1. Device Tree Compatibility

#define DT_DRV_COMPAT lowrisc_opentitan_aes

------------------------------------------------------
2. Header Includes

#include <stdint.h>                 // For fixed-width integer types (uint32_t)
#include <errno.h>                  // For error codes (-EINVAL, -ENOTSUP) returned by Zephyr APIs.
#include <string.h>                 // For memset() and memcpy() used in buffer and key manipulations.

#include <zephyr/kernel.h>          // the k_mutex used in our data struct for thread safety.
#include <zephyr/device.h>          // DEVICE_DT_INST_DEFINE macro to register the driver instance with the OS.
#include <zephyr/devicetree.h>      // For parsing the .dts files (e.g., DT_INST_REG_ADDR) to get hardware memory addresses.

#include <zephyr/sys/sys_io.h>      // For sys_read32() and sys_write32() to read/write to the memory-mapped registers.
#include <zephyr/sys/byteorder.h>   // To handle endianness when loading keys/data into the AES block.

#include <zephyr/crypto/crypto.h>   // (crypto_session, crypto_pkt).
#include <zephyr/crypto/cipher.h>   // (CRYPTO_CIPHER_MODE_CBC, CRYPTO_CIPHER_ALGO_AES).

#include <zephyr/logging/log.h>      // For the LOG_ERR(), LOG_INF(): Debugging
LOG_MODULE_REGISTER(opentitan_aes, CONFIG_CRYPTO_LOG_LEVEL);

#include "aes_regs.h"            // just in case

------------------------------------------------------
3. Register Offsets and Bitmasks (macro)

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
#define AES_CTRL_SHADOWED_KEY_LEN_VALUE_AES_256 0x4

#define AES_CTRL_SHADOWED_MANUAL_OPERATION_BIT 15

// Trigger Register
#define AES_TRIGGER_REG_OFFSET 0x80
#define AES_TRIGGER_START_BIT 0

// Status Register
#define AES_STATUS_REG_OFFSET 0x84
#define AES_STATUS_IDLE_BIT 0
#define AES_STATUS_OUTPUT_VALID_BIT 3
#define AES_STATUS_INPUT_READY_BIT 4

The rest of the definitions in aes_regs.h cover advanced features 
that fall outside the standard Zephyr OS Crypto API (<zephyr/crypto.h>). 
like: Fault-Injection/PRNGs/GCM
Including them now just adds dead code.
------------------------------------------------------
4. Configuration Structure


structs: config / data

struct opentitan_aes_config (ROM: Base address).
struct opentitan_aes_data (RAM)


------------------------------------------------------
5. Initialization and Reset

static int opentitan_aes_init(const struct device *dev) {
    // 1. Check if the device is ready
    // 2. Perform a hardware reset if necessary
    // 3. Initialize any OS locks (Mutex/Semaphores)
    return 0;
}

------------------------------------------------------
6. Read and Write Function

static void aes_write_block
static void aes_read_block
static void aes_process_block


------------------------------------------------------
7. AES Modes

static int opentitan_aes_ecb_op
static int opentitan_aes_cbc_op

------------------------------------------------------
8. Session Management

which aes mode was chosen


------------------------------------------------------
9. Zephyr Kernal threading functions 

Thread Safety Hooks / Locks / Polling Hooks


------------------------------------------------------
10. Hooking up the API

static DEVICE_API( ) = {

};


------------------------------------------------------
11. Device Instantiation 

#define OPENTITAN_AES_INIT(n).....


DT_INST_FOREACH_STATUS_OKAY(OPENTITAN_AES_INIT)