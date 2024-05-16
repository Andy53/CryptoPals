#ifndef _CRYPTO_HELPERS_H_
#define _CRYPTO_HELPERS_H_

#include <stdio.h>

extern int array_contains(unsigned char *bytes, unsigned char element, size_t bytes_len);
extern int hex_to_bytes(unsigned char *hex, unsigned char *bytes, size_t *bytes_len);
extern unsigned char *b64_encode(unsigned char *bytes, size_t bytes_len); //need to fix this.
extern int b64_decode(char *in, unsigned char *out, size_t *outlen);
extern int xor(unsigned char *bytes_1, unsigned char *bytes_2, unsigned char *bytes_3, size_t bytes_1_len, size_t bytes_2_len);
extern int edit_distance(unsigned char *bytes_1, unsigned char *bytes_2, size_t bytes_1_len, size_t *edit_distance);
extern int ecb_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *cipher_bytes, size_t plain_bytes_len, size_t *cipher_bytes_len);
extern int ecb_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *plain_bytes, size_t cipher_bytes_len, size_t *plain_bytes_len);
extern int cbc_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *iv, unsigned char *cipher_bytes, size_t plain_bytes_len, size_t *cipher_bytes_len);
extern int cbc_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *iv, unsigned char *plain_bytes, size_t cipher_bytes_len, size_t *plain_bytes_len);

#endif