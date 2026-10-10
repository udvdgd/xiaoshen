/*
 * xshen-c · 小神算法 桌面版 C CLI
 * AES-256-GCM (OpenSSL EVP) + PBKDF2-HMAC-SHA256 (40万). 容器 XSC1.
 *   xshen-c enc <输入> <输出> <密钥>
 *   xshen-c dec <输入> <输出> <密钥>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32
#define TAG_LEN 16
#define ITERATIONS 400000

static int derive(const char *pw, const unsigned char *salt, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), salt, SALT_LEN, ITERATIONS, EVP_sha256(), KEY_LEN, key);
}
static int read_file(const char *p, unsigned char **b, size_t *n) {
    FILE *f = fopen(p, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    *b = malloc((size_t)sz + 1);
    if (fread(*b, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return -1; }
    fclose(f); *n = (size_t)sz; return 0;
}
static int write_file(const char *p, const unsigned char *b, size_t n) {
    FILE *f = fopen(p, "wb"); if (!f) return -1;
    if (fwrite(b, 1, n, f) != n) { fclose(f); return -1; }
    fclose(f); return 0;
}
static int do_enc(const char *in, const char *out, const char *pw) {
    unsigned char *data; size_t n;
    if (read_file(in, &data, &n)) { perror("read"); return 1; }
    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], key[KEY_LEN];
    RAND_bytes(salt, SALT_LEN); RAND_bytes(nonce, NONCE_LEN);
    if (!derive(pw, salt, key)) { fprintf(stderr, "pbkdf2 failed\n"); return 1; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *ct = malloc(n + 16); int len = 0, ctlen = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ctx, ct, &len, data, (int)n); ctlen = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); ctlen += len;
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    FILE *f = fopen(out, "wb");
    fwrite("XSC1", 1, 4, f); fwrite(salt, 1, SALT_LEN, f); fwrite(nonce, 1, NONCE_LEN, f);
    fwrite(ct, 1, (size_t)ctlen, f); fwrite(tag, 1, TAG_LEN, f); fclose(f);
    printf("[+] 加密 %s -> %s (%d 字节密文)\n", in, out, ctlen);
    free(data); free(ct); return 0;
}
static int do_dec(const char *in, const char *out, const char *pw) {
    unsigned char *b; size_t n;
    if (read_file(in, &b, &n)) { perror("read"); return 1; }
    size_t hdr = 4 + SALT_LEN + NONCE_LEN;
    if (n < hdr + TAG_LEN || memcmp(b, "XSC1", 4)) { fprintf(stderr, "不是 XSC1 或损坏\n"); return 1; }
    const unsigned char *salt = b + 4, *nonce = salt + SALT_LEN, *ct = nonce + NONCE_LEN, *tag = b + n - TAG_LEN;
    size_t ctlen = n - hdr - TAG_LEN;
    unsigned char key[KEY_LEN];
    if (!derive(pw, salt, key)) { fprintf(stderr, "pbkdf2 failed\n"); return 1; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pt = malloc(ctlen + 16); int len = 0, ptlen = 0, rc = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ctlen); ptlen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);
    rc = EVP_DecryptFinal_ex(ctx, pt + len, &len); EVP_CIPHER_CTX_free(ctx);
    if (rc <= 0) { fprintf(stderr, "[!] 解密失败: 密钥错误或被篡改\n"); return 1; }
    ptlen += len;
    if (write_file(out, pt, (size_t)ptlen)) { perror("write"); return 1; }
    printf("[+] 解密 %s -> %s (%d 字节)\n", in, out, ptlen);
    free(b); free(pt); return 0;
}
int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "小神桌面 C CLI\n  %s enc <输入> <输出> <密钥>\n  %s dec <输入> <输出> <密钥>\n", argv[0], argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "enc")) return do_enc(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "dec")) return do_dec(argv[2], argv[3], argv[4]);
    fprintf(stderr, "未知命令\n"); return 1;
}
