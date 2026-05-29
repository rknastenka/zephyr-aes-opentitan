#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/crypto/cipher.h>
#include <zephyr/ztest.h>
#include <string.h>

/* --- Keys --- */
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

/* --- ECB vectors (single block) --- */
static const uint8_t ecb_pt[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static const uint8_t ecb_ct_128[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};
static const uint8_t ecb_ct_256[16] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
};

/* --- CBC vectors (2 blocks) --- */
static uint8_t cbc_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t cbc_pt[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static const uint8_t cbc_ct_128[32] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
};
static const uint8_t cbc_ct_256[32] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d
};

/* --- CTR vectors (2 blocks) --- */
static uint8_t ctr_iv[16] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};
static const uint8_t ctr_pt[32] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static const uint8_t ctr_ct_128[32] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
    0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff
};
static const uint8_t ctr_ct_256[32] = {
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5,
    0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
    0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a,
    0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5
};

/* --- Helpers --- */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printk("%s: ", label);
    for (size_t i = 0; i < len; i++) { printk("%02x ", buf[i]); }
    printk("\n");
}

static void run_ecb_test(const struct device *dev,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *input, size_t input_len,
                         const uint8_t *expected, enum cipher_op op)
{
    struct cipher_ctx s = {
        .keylen = key_len,
        .key.bit_stream = (uint8_t *)key,
        .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
    };
    zassert_ok(cipher_begin_session(dev, &s, CRYPTO_CIPHER_ALGO_AES,
                                    CRYPTO_CIPHER_MODE_ECB, op),
               "ECB begin_session failed");
    uint8_t out[32] = {0};
    struct cipher_pkt pkt = { .in_buf = (uint8_t *)input, .in_len = input_len,
                               .out_buf_max = sizeof(out), .out_buf = out };
    zassert_ok(cipher_block_op(&s, &pkt), "ECB op failed");
    print_hex(op == CRYPTO_CIPHER_OP_ENCRYPT ? "ECB ENC" : "ECB DEC", out, input_len);
    zassert_mem_equal(out, expected, input_len, "ECB mismatch");
    cipher_free_session(dev, &s);
}

static void run_cbc_test(const struct device *dev,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *iv,
                         const uint8_t *input, size_t input_len,
                         const uint8_t *expected, enum cipher_op op)
{
    uint8_t iv_copy[16]; memcpy(iv_copy, iv, 16);
struct cipher_ctx s = {
    .keylen = key_len,
    .key.bit_stream = (uint8_t *)key,
    .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
};
    zassert_ok(cipher_begin_session(dev, &s, CRYPTO_CIPHER_ALGO_AES,
                                    CRYPTO_CIPHER_MODE_CBC, op),
               "CBC begin_session failed");
    uint8_t out[32] = {0};
    struct cipher_pkt pkt = { .in_buf = (uint8_t *)input, .in_len = input_len,
                               .out_buf_max = sizeof(out), .out_buf = out };
    zassert_ok(cipher_cbc_op(&s, &pkt, iv_copy), "CBC op failed");
    print_hex(op == CRYPTO_CIPHER_OP_ENCRYPT ? "CBC ENC" : "CBC DEC", out, input_len);
    zassert_mem_equal(out, expected, input_len, "CBC mismatch");
    cipher_free_session(dev, &s);
}

static void run_ctr_test(const struct device *dev,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *ctr,
                         const uint8_t *input, size_t input_len,
                         const uint8_t *expected, enum cipher_op op)
{
    uint8_t ctr_copy[16]; memcpy(ctr_copy, ctr, 16);
struct cipher_ctx s = {
    .keylen = key_len,
    .key.bit_stream = (uint8_t *)key,
    .flags = CAP_RAW_KEY | CAP_SEPARATE_IO_BUFS | CAP_SYNC_OPS,
};
    zassert_ok(cipher_begin_session(dev, &s, CRYPTO_CIPHER_ALGO_AES,
                                    CRYPTO_CIPHER_MODE_CTR, op),
               "CTR begin_session failed");
    uint8_t out[32] = {0};
    struct cipher_pkt pkt = { .in_buf = (uint8_t *)input, .in_len = input_len,
                               .out_buf_max = sizeof(out), .out_buf = out };
    zassert_ok(cipher_ctr_op(&s, &pkt, ctr_copy), "CTR op failed");
    print_hex(op == CRYPTO_CIPHER_OP_ENCRYPT ? "CTR ENC" : "CTR DEC", out, input_len);
    zassert_mem_equal(out, expected, input_len, "CTR mismatch");
    cipher_free_session(dev, &s);
}

/* =======================================================================
 * Tests
 * ===================================================================== */
ZTEST_SUITE(aes_tests, NULL, NULL, NULL, NULL, NULL);

/* ECB */
ZTEST(aes_tests, test_ecb_128_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
    run_ecb_test(dev, key128, sizeof(key128), ecb_pt, sizeof(ecb_pt), ecb_ct_128, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_ecb_128_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
    run_ecb_test(dev, key128, sizeof(key128), ecb_ct_128, sizeof(ecb_ct_128), ecb_pt, CRYPTO_CIPHER_OP_DECRYPT);
}
ZTEST(aes_tests, test_ecb_256_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
    run_ecb_test(dev, key256, sizeof(key256), ecb_pt, sizeof(ecb_pt), ecb_ct_256, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_ecb_256_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
    run_ecb_test(dev, key256, sizeof(key256), ecb_ct_256, sizeof(ecb_ct_256), ecb_pt, CRYPTO_CIPHER_OP_DECRYPT);
}

/* CBC */
ZTEST(aes_tests, test_cbc_128_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_cbc_test(dev, key128, sizeof(key128), cbc_iv, cbc_pt, sizeof(cbc_pt), cbc_ct_128, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_cbc_128_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_cbc_test(dev, key128, sizeof(key128), cbc_iv, cbc_ct_128, sizeof(cbc_ct_128), cbc_pt, CRYPTO_CIPHER_OP_DECRYPT);
}
ZTEST(aes_tests, test_cbc_256_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_cbc_test(dev, key256, sizeof(key256), cbc_iv, cbc_pt, sizeof(cbc_pt), cbc_ct_256, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_cbc_256_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_cbc_test(dev, key256, sizeof(key256), cbc_iv, cbc_ct_256, sizeof(cbc_ct_256), cbc_pt, CRYPTO_CIPHER_OP_DECRYPT);
}

/* CTR */
ZTEST(aes_tests, test_ctr_128_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_ctr_test(dev, key128, sizeof(key128), ctr_iv, ctr_pt, sizeof(ctr_pt), ctr_ct_128, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_ctr_128_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_ctr_test(dev, key128, sizeof(key128), ctr_iv, ctr_ct_128, sizeof(ctr_ct_128), ctr_pt, CRYPTO_CIPHER_OP_DECRYPT);
}
ZTEST(aes_tests, test_ctr_256_encrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_ctr_test(dev, key256, sizeof(key256), ctr_iv, ctr_pt, sizeof(ctr_pt), ctr_ct_256, CRYPTO_CIPHER_OP_ENCRYPT);
}
ZTEST(aes_tests, test_ctr_256_decrypt) {
    const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(aes0));
    zassert_true(device_is_ready(dev), "not ready");
#if defined(CONFIG_CRYPTO_OPENTITAN_AES_RENODE_COMPAT)
    ztest_test_skip();
#endif
    run_ctr_test(dev, key256, sizeof(key256), ctr_iv, ctr_ct_256, sizeof(ctr_ct_256), ctr_pt, CRYPTO_CIPHER_OP_DECRYPT);
}
