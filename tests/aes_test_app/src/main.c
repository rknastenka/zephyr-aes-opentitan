#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/cipher.h>
#include <zephyr/ztest.h>
#include <string.h>

static const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static const uint8_t expected_ciphertext[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};

ZTEST_SUITE(aes_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(aes_tests, test_aes_ecb_encrypt)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    struct cipher_ctx session = {
        .keylen = sizeof(key),
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
    for (int i=0; i<16; i++) printk("%02x ", output[i]);
    printk("\n");

    zassert_mem_equal(output, expected_ciphertext, 16,
                      "Ciphertext does not match NIST expected value");

    cipher_free_session(dev, &session);
}