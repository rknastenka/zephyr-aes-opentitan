#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/cipher.h>
#include <zephyr/ztest.h>
#include <string.h>

/*
 * Combined AES test file with dynamic summary:
 * - ECB tests run in Renode
 * - CBC / CTR tests can be skipped dynamically depending on environment
 * - Final summary reflects actual runtime results
 */

/* ================================================================
 * Result tracking
 * ================================================================ */

enum test_result_state {
    RESULT_NOT_RUN = 0,
    RESULT_PASSED,
    RESULT_SKIPPED,
    RESULT_FAILED,
};

enum aes_test_id {
    TEST_ECB_128 = 0,
    TEST_ECB_256,
    TEST_CBC_128,
    TEST_CBC_256,
    TEST_CTR_128,
    TEST_CTR_256,
    TEST_COUNT
};

static enum test_result_state g_test_results[TEST_COUNT];

static const char *test_name(enum aes_test_id id)
{
    switch (id) {
    case TEST_ECB_128: return "ECB-128 encrypt/decrypt";
    case TEST_ECB_256: return "ECB-256 encrypt/decrypt";
    case TEST_CBC_128: return "CBC-128 encrypt/decrypt";
    case TEST_CBC_256: return "CBC-256 encrypt/decrypt";
    case TEST_CTR_128: return "CTR-128 encrypt/decrypt";
    case TEST_CTR_256: return "CTR-256 encrypt/decrypt";
    default: return "UNKNOWN";
    }
}

static const char *result_name(enum test_result_state state)
{
    switch (state) {
    case RESULT_PASSED: return "PASSED";
    case RESULT_SKIPPED: return "SKIPPED";
    case RESULT_FAILED: return "FAILED";
    case RESULT_NOT_RUN:
    default: return "NOT RUN";
    }
}

/* ================================================================
 * ECB vectors
 * ================================================================ */

static const uint8_t ecb_key128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t ecb_key256[32] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t ecb_plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

static const uint8_t ecb_expected_ct_128[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};

static const uint8_t ecb_expected_ct_256[16] = {
    0x06, 0x51, 0xe1, 0xd4, 0x0c, 0x39, 0xfc, 0x50,
    0x42, 0x43, 0x9c, 0x6f, 0x8f, 0x13, 0x9f, 0xf2
};

/* ================================================================
 * CBC / CTR vectors
 * ================================================================ */

static const uint8_t plaintext_64[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const uint8_t key128[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t key256[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static const uint8_t cbc_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t cbc_ct_128[64] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
    0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
    0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

static const uint8_t cbc_ct_256[64] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
    0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
    0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};

static const uint8_t ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const uint8_t ctr_ct_128[64] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
    0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
    0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
};

static const uint8_t ctr_ct_256[64] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
    0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
    0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
    0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6,
    0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6
};

/* ================================================================
 * ECB runner
 * ================================================================ */

static void run_ecb_enc_dec(const struct device *dev,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *expected_ct,
                            const char *label)
{
    int ret;

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
        .in_buf      = (uint8_t *)ecb_plaintext,
        .in_len      = sizeof(ecb_plaintext),
        .out_buf_max = sizeof(ciphertext),
        .out_buf     = ciphertext,
    };

    ret = cipher_block_op(&enc_ctx, &enc_pkt);
    zassert_ok(ret, "[%s] cipher_block_op (ENC) failed: %d", label, ret);

    zassert_mem_equal(ciphertext, expected_ct, 16,
                      "[%s] Ciphertext != NIST expected", label);

    cipher_free_session(dev, &enc_ctx);

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

    zassert_mem_equal(decrypted, ecb_plaintext, 16,
                      "[%s] Decrypted != original plaintext", label);

    cipher_free_session(dev, &dec_ctx);
}

/* ================================================================
 * CBC runner
 * ================================================================ */

static void run_cbc_enc_dec(const struct device *dev,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *expected_ct,
                            const char *label)
{
    int ret;
    uint8_t iv_enc[16];
    uint8_t iv_dec[16];

    memcpy(iv_enc, cbc_iv, sizeof(iv_enc));
    memcpy(iv_dec, cbc_iv, sizeof(iv_dec));

    struct cipher_ctx enc_ctx = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &enc_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CBC,
                               CRYPTO_CIPHER_OP_ENCRYPT);
    zassert_ok(ret, "[%s] CBC begin encrypt failed: %d", label, ret);

    uint8_t ciphertext[64] = {0};
    struct cipher_pkt enc_pkt = {
        .in_buf = (uint8_t *)plaintext_64,
        .in_len = sizeof(plaintext_64),
        .out_buf = ciphertext,
        .out_buf_max = sizeof(ciphertext),
    };

    ret = cipher_cbc_op(&enc_ctx, &enc_pkt, iv_enc);
    zassert_ok(ret, "[%s] CBC encrypt failed: %d", label, ret);

    zassert_mem_equal(ciphertext, expected_ct, sizeof(ciphertext),
                      "[%s] CBC ciphertext mismatch", label);

    cipher_free_session(dev, &enc_ctx);

    struct cipher_ctx dec_ctx = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &dec_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CBC,
                               CRYPTO_CIPHER_OP_DECRYPT);
    zassert_ok(ret, "[%s] CBC begin decrypt failed: %d", label, ret);

    uint8_t decrypted[64] = {0};
    struct cipher_pkt dec_pkt = {
        .in_buf = ciphertext,
        .in_len = sizeof(ciphertext),
        .out_buf = decrypted,
        .out_buf_max = sizeof(decrypted),
    };

    ret = cipher_cbc_op(&dec_ctx, &dec_pkt, iv_dec);
    zassert_ok(ret, "[%s] CBC decrypt failed: %d", label, ret);

    zassert_mem_equal(decrypted, plaintext_64, sizeof(decrypted),
                      "[%s] CBC decrypted plaintext mismatch", label);

    cipher_free_session(dev, &dec_ctx);
}

/* ================================================================
 * CTR runner
 * ================================================================ */

static void run_ctr_enc_dec(const struct device *dev,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *expected_ct,
                            const char *label)
{
    int ret;
    uint8_t ctr_enc[16];
    uint8_t ctr_dec[16];

    memcpy(ctr_enc, ctr_iv, sizeof(ctr_enc));
    memcpy(ctr_dec, ctr_iv, sizeof(ctr_dec));

    struct cipher_ctx enc_ctx = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &enc_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CTR,
                               CRYPTO_CIPHER_OP_ENCRYPT);
    zassert_ok(ret, "[%s] CTR begin encrypt failed: %d", label, ret);

    uint8_t ciphertext[64] = {0};
    struct cipher_pkt enc_pkt = {
        .in_buf = (uint8_t *)plaintext_64,
        .in_len = sizeof(plaintext_64),
        .out_buf = ciphertext,
        .out_buf_max = sizeof(ciphertext),
    };

    ret = cipher_ctr_op(&enc_ctx, &enc_pkt, ctr_enc);
    zassert_ok(ret, "[%s] CTR encrypt failed: %d", label, ret);

    zassert_mem_equal(ciphertext, expected_ct, sizeof(ciphertext),
                      "[%s] CTR ciphertext mismatch", label);

    cipher_free_session(dev, &enc_ctx);

    struct cipher_ctx dec_ctx = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };

    ret = cipher_begin_session(dev, &dec_ctx,
                               CRYPTO_CIPHER_ALGO_AES,
                               CRYPTO_CIPHER_MODE_CTR,
                               CRYPTO_CIPHER_OP_DECRYPT);
    zassert_ok(ret, "[%s] CTR begin decrypt failed: %d", label, ret);

    uint8_t decrypted[64] = {0};
    struct cipher_pkt dec_pkt = {
        .in_buf = ciphertext,
        .in_len = sizeof(ciphertext),
        .out_buf = decrypted,
        .out_buf_max = sizeof(decrypted),
    };

    ret = cipher_ctr_op(&dec_ctx, &dec_pkt, ctr_dec);
    zassert_ok(ret, "[%s] CTR decrypt failed: %d", label, ret);

    zassert_mem_equal(decrypted, plaintext_64, sizeof(decrypted),
                      "[%s] CTR decrypted plaintext mismatch", label);

    cipher_free_session(dev, &dec_ctx);
}

/* ================================================================
 * Test suites
 * ================================================================ */

ZTEST_SUITE(aes_ecb_tests, NULL, NULL, NULL, NULL, NULL);
ZTEST_SUITE(aes_modes_tests, NULL, NULL, NULL, NULL, NULL);
ZTEST_SUITE(aes_summary_tests, NULL, NULL, NULL, NULL, NULL);

/* ================================================================
 * ECB tests
 * ================================================================ */

ZTEST(aes_ecb_tests, test_ecb_128)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    g_test_results[TEST_ECB_128] = RESULT_SKIPPED;
    ztest_test_skip();
#endif

    run_ecb_enc_dec(dev, ecb_key128, sizeof(ecb_key128),
                    ecb_expected_ct_128, "AES-128 ECB");

    g_test_results[TEST_ECB_128] = RESULT_PASSED;
}

ZTEST(aes_ecb_tests, test_ecb_256)
{
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_ecb_enc_dec(dev, ecb_key256, sizeof(ecb_key256),
                    ecb_expected_ct_256, "AES-256 ECB");

    g_test_results[TEST_ECB_256] = RESULT_PASSED;
}

/* ================================================================
 * CBC tests
 * ================================================================ */

ZTEST(aes_modes_tests, test_aes_cbc_128)
{
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    g_test_results[TEST_CBC_128] = RESULT_SKIPPED;
    ztest_test_skip();
#endif

    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_cbc_enc_dec(dev, key128, sizeof(key128), cbc_ct_128, "AES-128 CBC");

    g_test_results[TEST_CBC_128] = RESULT_PASSED;
}

ZTEST(aes_modes_tests, test_aes_cbc_256)
{
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    g_test_results[TEST_CBC_256] = RESULT_SKIPPED;
    ztest_test_skip();
#endif

    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_cbc_enc_dec(dev, key256, sizeof(key256), cbc_ct_256, "AES-256 CBC");

    g_test_results[TEST_CBC_256] = RESULT_PASSED;
}

/* ================================================================
 * CTR tests
 * ================================================================ */

ZTEST(aes_modes_tests, test_aes_ctr_128)
{
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    g_test_results[TEST_CTR_128] = RESULT_SKIPPED;
    ztest_test_skip();
#endif

    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_ctr_enc_dec(dev, key128, sizeof(key128), ctr_ct_128, "AES-128 CTR");

    g_test_results[TEST_CTR_128] = RESULT_PASSED;
}

ZTEST(aes_modes_tests, test_aes_ctr_256)
{
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    g_test_results[TEST_CTR_256] = RESULT_SKIPPED;
    ztest_test_skip();
#endif

    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "AES device not ready");

    run_ctr_enc_dec(dev, key256, sizeof(key256), ctr_ct_256, "AES-256 CTR");

    g_test_results[TEST_CTR_256] = RESULT_PASSED;
}

/* ================================================================
 * Final summary
 * ================================================================ */

ZTEST(aes_summary_tests, test_zzzz_print_summary)
{
    printk("\n");
    printk("====================================\n");
    printk("         AES TEST SUMMARY\n");
    printk("====================================\n");

    for (int i = 0; i < TEST_COUNT; i++) {
        printk("%-24s : %s\n", test_name((enum aes_test_id)i),
               result_name(g_test_results[i]));
    }

    printk("====================================\n");
}