------------------------------------------------------
1. Device Tree Compatibility

#define DT_DRV_COMPAT lowrisc_opentitan_aes

------------------------------------------------------
2. Header Includes

#include 


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