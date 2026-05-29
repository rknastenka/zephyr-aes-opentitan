#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/cipher.h>
#include <zephyr/ztest.h>
#include <string.h>

/* ================================================================
 * NIST AES-ECB Test Vectors
 * Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
 * ================================================================ */

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

static const uint8_t expected_ct_128[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};

static const uint8_t expected_ct_256[16] = {
    0x06, 0x51, 0xe1, 0xd4, 0x0c, 0x39, 0xfc, 0x50,
    0x42, 0x43, 0x9c, 0x6f, 0x8f, 0x13, 0x9f, 0xf2
};

/* ================================================================
 * Helper: print 16-byte buffer as hex
 * ================================================================ */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("[%s] ", label);
    for (size_t i = 0; i < len; i++) {
        printk("%02x ", buf[i]);
    }
    printk("\n");
}

static void run_ecb_enc_dec(const struct device *dev,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *expected_ct,
                            const char *label)
{
    int ret;

    printk("\n====== %s ======\n", label);

    /* ----------------------------------------------------------
     * ENCRYPT
     * ---------------------------------------------------------- */
    printk("\n[LOG 1] Input plaintext (before encrypt):\n");
    print_hex("PLAINTEXT", plaintext, sizeof(plaintext));

    struct cipher_ctx enc_ctx = {
        .keylen         = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags          = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &enc_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_ECB,
                               CRYPTO_CIPHER_OP_ENCRYPT);
    zassert_ok(ret, "[%s] cipher_begin_session (ENC) failed: %d", label, ret);

    uint8_t ciphertext[16] = {0};
    struct cipher_pkt enc_pkt = {
        .in_buf      = (uint8_t *)plaintext,
        .in_len      = sizeof(plaintext),
        .out_buf_max = sizeof(ciphertext),
        .out_buf     = ciphertext,
    };

    ret = cipher_block_op(&enc_ctx, &enc_pkt);
    zassert_ok(ret, "[%s] cipher_block_op (ENC) failed: %d", label, ret);

    printk("\n[LOG 2] Ciphertext output (after encrypt):\n");
    print_hex("CIPHERTEXT", ciphertext, sizeof(ciphertext));

    printk("\n[LOG 3] Expected ciphertext (NIST reference):\n");
    print_hex("EXPECTED  ", expected_ct, 16);

    zassert_mem_equal(ciphertext, expected_ct, 16,
                      "[%s] Ciphertext != NIST expected", label);
    printk("[%s] ENCRYPT PASSED\n", label);

    cipher_free_session(dev, &enc_ctx);

    /* ----------------------------------------------------------
     * DECRYPT — feed the ciphertext we just produced back in
     * ---------------------------------------------------------- */
    printk("\n[LOG 4] Input to decrypt (ciphertext from step above):\n");
    print_hex("CT IN     ", ciphertext, sizeof(ciphertext));

    struct cipher_ctx dec_ctx = {
        .keylen         = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags          = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &dec_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_ECB,
                               CRYPTO_CIPHER_OP_DECRYPT);
    zassert_ok(ret, "[%s] cipher_begin_session (DEC) failed: %d", label, ret);

    uint8_t decrypted[16] = {0};
    struct cipher_pkt dec_pkt = {
        .in_buf      = ciphertext,
        .in_len      = sizeof(ciphertext),
        .out_buf_max = sizeof(decrypted),
        .out_buf     = decrypted,
    };

    ret = cipher_block_op(&dec_ctx, &dec_pkt);
    zassert_ok(ret, "[%s] cipher_block_op (DEC) failed: %d", label, ret);

    printk("\n[LOG 5] Recovered plaintext (after decrypt):\n");
    print_hex("DECRYPTED ", decrypted, sizeof(decrypted));

    printk("\n[LOG 6] Original plaintext (reference check):\n");
    print_hex("ORIGINAL  ", plaintext, sizeof(plaintext));

    zassert_mem_equal(decrypted, plaintext, 16,
                      "[%s] Decrypted != original plaintext", label);
    printk("[%s] DECRYPT PASSED\n", label);

    cipher_free_session(dev, &dec_ctx);

    printk("\n====== %s: ALL PASSED ======\n\n", label);
}

/* ================================================================
 * ZTest suite — ECB only
 * ================================================================ */
ZTEST_SUITE(aes_ecb_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(aes_ecb_tests, test_ecb_128)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif

    run_ecb_enc_dec(dev, key128, sizeof(key128),
                    expected_ct_128, "AES-128 ECB");
}

ZTEST(aes_ecb_tests, test_ecb_256)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_ecb_enc_dec(dev, key256, sizeof(key256),
                    expected_ct_256, "AES-256 ECB");
}