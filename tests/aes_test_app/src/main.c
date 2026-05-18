#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/cipher.h>
#include <zephyr/ztest.h>
#include <string.h>

static const uint8_t key128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t key256[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static const uint8_t expected_ciphertext_128[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};
static const uint8_t expected_ciphertext_256[16] = {
    0x06, 0x51, 0xe1, 0xd4, 0x0c, 0x39, 0xfc, 0x50,
    0x42, 0x43, 0x9c, 0x6f, 0x8f, 0x13, 0x9f, 0xf2
};

static void run_aes_ecb_test(const struct device *dev,
                             const uint8_t *key,
                             size_t key_len,
                             const uint8_t *expected)
{
    struct cipher_ctx session = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    int ret = cipher_begin_session(dev, &session,
                                   CRYPTO_CIPHER_ALGO_AES,
                                   CRYPTO_CIPHER_MODE_ECB,
                                   CRYPTO_CIPHER_OP_ENCRYPT);
    zassert_ok(ret, "Failed to begin AES session: %d", ret);

    uint8_t output[16] = {0};
    struct cipher_pkt pkt = {
        .in_buf     = (uint8_t *)plaintext,
        .in_len     = sizeof(plaintext),
        .out_buf_max = sizeof(output),
        .out_buf    = output,
    };

    ret = cipher_block_op(&session, &pkt);
    zassert_ok(ret, "Encryption failed: %d", ret);

    printk("OUTPUT: ");
    for (int i = 0; i < 16; i++) {
        printk("%02x ", output[i]);
    }
    printk("\n");

    zassert_mem_equal(output, expected, 16,
                      "Ciphertext does not match NIST expected value");

    cipher_free_session(dev, &session);
}

ZTEST_SUITE(aes_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(aes_tests, test_aes_ecb_encrypt_128)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif

    run_aes_ecb_test(dev, key128, sizeof(key128), expected_ciphertext_128);
}

ZTEST(aes_tests, test_aes_ecb_encrypt_256)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_aes_ecb_test(dev, key256, sizeof(key256), expected_ciphertext_256);
}