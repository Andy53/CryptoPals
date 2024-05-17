#ifndef _CRYPTO_HELPERS_H_
#define _CRYPTO_HELPERS_H_

#include <stdio.h>

extern int array_contains(unsigned char *bytes, unsigned char element, int bytes_len);
extern int hex_to_bytes(unsigned char *hex, unsigned char *bytes, int *bytes_len);
extern unsigned char *b64_encode(unsigned char *bytes, int bytes_len); //need to fix this.
extern int b64_decode(char *in, unsigned char *out, int *outlen);
extern int xor(unsigned char *bytes_1, unsigned char *bytes_2, unsigned char *bytes_3, int bytes_1_len, int bytes_2_len);
extern int edit_distance(unsigned char *bytes_1, unsigned char *bytes_2, int bytes_1_len, int *edit_distance);
extern int ecb_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *cipher_bytes, int plain_bytes_len, int *cipher_bytes_len);
extern int ecb_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *plain_bytes, int cipher_bytes_len, int *plain_bytes_len);
extern int cbc_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *iv, unsigned char *cipher_bytes, int plain_bytes_len, int *cipher_bytes_len);
extern int cbc_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *iv, unsigned char *plain_bytes, int cipher_bytes_len, int *plain_bytes_len);

#endif