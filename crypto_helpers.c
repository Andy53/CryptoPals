#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "PKCS7.h"

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

int array_contains(unsigned char *bytes, unsigned char element, int bytes_len) {
	for(int i = 0; i < bytes_len; i++) {
        if(bytes[i] == element)
            return 1;
    }
    return 0;
}

int hex_encode(char *hex, char *bytes, int *bytes_len) {
    if (hex == NULL || bytes_len == 0)
		return 1;
	
	int length = strlen(hex) % 2 ? strlen(hex) + 1 : strlen(hex);
    unsigned char checkedHex[length];
    
    for (int i = 0; i <= length; i++) {
        if (i == 0 && strlen(hex) % 2){
            checkedHex[0] = '0';
        }
        else if (i == length){
            checkedHex[i] = '\x00';
        }
        else {
            checkedHex[i] = hex[i]; 
        } 
    }
    
    *bytes_len = length / 2;
    int counter = 0;
    for (int i = 0; i < length / 2; i++){
		int check = sscanf((const char *)&checkedHex[counter], "%2hhx", &bytes[i]);
		if (check != 1)
			return 2; 
        counter += 2;
    }
	return 0;
}

unsigned char *b64_encode(unsigned char *bytes, int bytes_len) {
	unsigned char *out;
	int  elen;
	int  i;
	int  j;
	int  v;

	if (bytes == NULL || bytes_len == 0)
		return NULL;

	elen = bytes_len;
	if (bytes_len % 3 != 0)
		elen += 3 - (bytes_len % 3);
	elen /= 3;
	elen *= 4;

	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<bytes_len; i+=3, j+=4) {
		v = bytes[i];
		v = i+1 < bytes_len ? v << 8 | bytes[i+1] : v << 8;
		v = i+2 < bytes_len ? v << 8 | bytes[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < bytes_len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < bytes_len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

int b64_decode(const char *bytes, unsigned char *out, int *outlen) {
	int len;
	int i;
	int j;
	int    v;

	if (bytes == NULL)
		return 1;

	len = strlen(bytes);
	int b64_decoded_size = 0;
	
	b64_decoded_size = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (bytes[i] == '=') {
			b64_decoded_size--;
		} else {
			break;
		}
	}

	if (*outlen < b64_decoded_size || len % 4 != 0 || out == NULL) {
		*outlen = b64_decoded_size;
		return 2;
	} else {
		*outlen = b64_decoded_size;
	}
		

	for (i=0; i<len; i++) {
		bool invalid_char = true;
		if (bytes[i] >= '0' && bytes[i] <= '9')
			invalid_char = false;
		else if (bytes[i] >= 'A' && bytes[i] <= 'Z')
			invalid_char = false;
		else if (bytes[i] >= 'a' && bytes[i] <= 'z')
			invalid_char = false;
		else if (bytes[i] == '+' || bytes[i] == '/' || bytes[i] == '=')
			invalid_char = false;

		if (invalid_char == true)
			return 3;
	}

	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[bytes[i]-43];
		v = (v << 6) | b64invs[bytes[i+1]-43];
		v = bytes[i+2]=='=' ? v << 6 : (v << 6) | b64invs[bytes[i+2]-43];
		v = bytes[i+3]=='=' ? v << 6 : (v << 6) | b64invs[bytes[i+3]-43];

		out[j] = (v >> 16) & 0xFF;
		if (bytes[i+2] != '=')
			out[j+1] = (v >> 8) & 0xFF;
		if (bytes[i+3] != '=')
			out[j+2] = v & 0xFF;
	}

	return 0;
}

int xor(unsigned char *bytes_1, unsigned char *bytes_2, unsigned char *bytes_3, int bytes_1_len, int bytes_2_len) {
	if (bytes_1 == NULL || bytes_2 == NULL || bytes_3 == NULL || bytes_1_len == 0 || bytes_2_len == 0)
		return 1;

	if (bytes_1_len >= bytes_2_len) {
		int short_counter = 0;
		for (int i = 0; i < bytes_1_len; i++) {
			if(short_counter >= bytes_2_len)
				short_counter = 0;
			bytes_3[i] = bytes_1[i] ^ bytes_2[short_counter];
			short_counter++;
		}
	}
	else  {
		int short_counter = 0;
		for (int i = 0; i < bytes_2_len; i++) {
			if(short_counter >= bytes_1_len)
				short_counter = 0;
			bytes_3[i] = bytes_1[short_counter] ^ bytes_2[i];
			short_counter++;
		}
	}
	return 0;
}

int edit_distance(unsigned char *bytes_1, unsigned char *bytes_2, int bytes_1_len, int *edit_dist) {
	for(int i = 0; i < bytes_1_len; i++){
		char val = bytes_1[i] ^ bytes_2[i];
		while(val) {
			val &= val - 1;
			*edit_dist += 1; 
		}
	}
	
	return 0;
}

int ecb_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *cipher_bytes, int plain_bytes_len, int *cipher_bytes_len) {
	EVP_CIPHER_CTX *ctx;
    int len = 0;
	unsigned char *padded_message = NULL;

	int padded_length = plain_bytes_len % 16 > 0 ? plain_bytes_len + (16 - (plain_bytes_len % 16)) : plain_bytes_len;

	PKCS7_Padding *padded   = addPadding(plain_bytes, plain_bytes_len, padded_length);
	padded_message    = padded->dataWithPadding;
	plain_bytes_len = padded->dataLengthWithPadding;

	if(*cipher_bytes_len != plain_bytes_len){
		*cipher_bytes_len = plain_bytes_len;
		return 1;
	}

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 2;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        return 3;

    if(1 != EVP_EncryptUpdate(ctx, cipher_bytes, &len, padded_message, plain_bytes_len))
        return 4;
    *cipher_bytes_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, cipher_bytes + *cipher_bytes_len, &len))
        return 5;

    EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int ecb_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *plain_bytes, int cipher_bytes_len, int *plain_bytes_len) {
	EVP_CIPHER_CTX *ctx;
    int len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 1;

	EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        return 2;

    if(1 != EVP_DecryptUpdate(ctx, plain_bytes, &len, cipher_bytes, cipher_bytes_len))
        return 3;
    *plain_bytes_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plain_bytes + *plain_bytes_len, &len))
        return 4;

    EVP_CIPHER_CTX_free(ctx);
	return 0;
}

int cbc_encrypt(unsigned char *plain_bytes, unsigned char *key, unsigned char *iv, unsigned char *cipher_bytes, 
				int plain_bytes_len, int *cipher_bytes_len) {
	
	int block_size = 16;
	int padded_length = plain_bytes_len % 16 > 0 ? plain_bytes_len + (16 - (plain_bytes_len % 16)) : plain_bytes_len;
	
	PKCS7_Padding *padded   = addPadding(plain_bytes, plain_bytes_len, padded_length);
    unsigned char *padded_message    = padded->dataWithPadding;
    plain_bytes_len = padded->dataLengthWithPadding;

	if(*cipher_bytes_len != plain_bytes_len) {
		*cipher_bytes_len = plain_bytes_len;
		return 2;
	}

	int total_blocks = plain_bytes_len / 16;
	unsigned char encrypted_bytes[plain_bytes_len];

	for(int i = 0; i < total_blocks; i++) {
		unsigned char current_block[16] = {0};
		unsigned char next_block[16] = {0};
		unsigned char encrypted_block[16] = {0};
		unsigned char decrypted_block[16] = {0};

		for (int j = 0; j < 16; j++)
			current_block[j] = i == 0 ? padded_message[j] ^ iv[j] : padded_message[j + (i * 16)] ^ cipher_bytes[j + ((i - 1) * 16)];

		ecb_encrypt(current_block, key, (unsigned char *) &encrypted_block, block_size, &block_size);
		ecb_decrypt(encrypted_block, key, (unsigned char *) &decrypted_block, block_size, &block_size);
		memcpy(cipher_bytes + i * 16, encrypted_block, 16);
	}
	return 1;
}

int cbc_decrypt(unsigned char *cipher_bytes, unsigned char *key, unsigned char *iv, unsigned char *plain_bytes, 
				int cipher_bytes_len, int *plain_bytes_len) {

	if(cipher_bytes_len % 16 != 0) {
		return 2;
	}

	if(cipher_bytes_len != *plain_bytes_len) {
		*plain_bytes_len = cipher_bytes_len;
		return 3;
	}

	int total_blocks = cipher_bytes_len / 16;
	int block_size = 16;

	for(int i = total_blocks - 1; i >= 0; i--) {
		unsigned char xored_block[16] = {0};
		unsigned char next_block[16] = {0};
		unsigned char encrypted_block[16] = {0};
		unsigned char plain_block[16] = {0};

		memcpy(encrypted_block, cipher_bytes + i * 16, 16);
		memcpy(next_block, cipher_bytes + (i - 1) * 16, 16);
		ecb_decrypt(encrypted_block, key, (unsigned char *) &xored_block, block_size, &block_size);

		for (int j = 0; j < 16; j++)
			plain_block[j] = i == 0 ? xored_block[j] ^ iv[j] : xored_block[j] ^ next_block[j];

		memcpy(plain_bytes + i * 16, plain_block, 16);
	}

	return 1;
}