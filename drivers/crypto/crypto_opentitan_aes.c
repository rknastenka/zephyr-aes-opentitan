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

#define 

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