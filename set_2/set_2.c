#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "../PKCS7.h"
#include "../crypto_helpers.h"

int challenge_9() {
    unsigned char message[] = "YELLOW SUBMARINE";
    PKCS7_Padding *padded   = addPadding(message, 16, 20);
    char *padded_message    = padded->dataWithPadding;

    printf("Challenge 9: YELLOW SUBMARINE with PCKS#7 padding = ");
    for(int i = 0; i < padded->dataLengthWithPadding; i++) {
        printf("\\x%02X", padded_message[i]);
    }
    printf("\n");

    return 1;
}

int challenge_10() {
    FILE *fp                   = fopen("challenge_10_inputs.txt", "r");
    unsigned char key[]        = "YELLOW SUBMARINE";
    unsigned char iv[16]       = {0};
    unsigned char *cipher_text = NULL;
    int cipher_text_len     = 0;
    int cipher_bytes_len    = 0;
    int plain_bytes_len     = 0;

    if(fp != NULL) {
        if(fseek(fp, 0L, SEEK_END) == 0) {
            long bufsize = ftell(fp);
            if(bufsize == -1)
                return 2;

            cipher_text = malloc(sizeof(char) * (bufsize + 1));

            if(fseek(fp, 0L, SEEK_SET) != 0)
                return 3;

            cipher_text_len = fread(cipher_text, sizeof(char), bufsize, fp);
            if( ferror( fp ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                cipher_text[cipher_text_len++] = '\0'; 
            }
        }
        fclose(fp);
    }
    else 
        return 4;

    b64_decode(cipher_text, NULL, &cipher_bytes_len);
    unsigned char cipher_bytes[cipher_bytes_len];
    b64_decode(cipher_text, cipher_bytes, &cipher_bytes_len);

    cbc_decrypt(cipher_bytes, key, iv, NULL, cipher_bytes_len, &plain_bytes_len);
    unsigned char plain_bytes[plain_bytes_len];
    cbc_decrypt(cipher_bytes, key, iv, plain_bytes, cipher_bytes_len, &plain_bytes_len);

    printf("Challenge 10: \n");
    for(int i = 0; i < plain_bytes_len; i++) {
        printf("%c", plain_bytes[i]);
    }
    printf("\n");
    return 1;
}

int challenge_11() {
    unsigned char key[16]  = {0};
    unsigned char iv[16]   = {0};
    unsigned char *plain_text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    
    srand ( time(NULL) );
    int bytes_before       = rand() % (10 + 1);
    int bytes_after        = rand() % (10 + 1);
    int mod_plain_text_len = strlen((const char *) plain_text) + bytes_before + bytes_after;
    unsigned char mod_plain_text[mod_plain_text_len];

    int cipher_bytes_len = 0;
    int total_blocks = 0;
    bool ecb = false;

    for(int i = 0; i < 16; i++)
        key[i] = rand();

    for(int i = 0; i < mod_plain_text_len; i++)
        if(i < bytes_before || i > strlen(plain_text) + bytes_before)
            mod_plain_text[i] = rand();
        else
            mod_plain_text[i] = plain_text[i - bytes_before];

    int mode = rand() % 2;
    if(mode == 0)
        ecb_encrypt(plain_text, key, NULL, mod_plain_text_len, &cipher_bytes_len);
    else
        cbc_encrypt(plain_text, key, iv, NULL, mod_plain_text_len, &cipher_bytes_len);

    unsigned char cipher_bytes[cipher_bytes_len];
    if(mode == 0)
        ecb_encrypt(plain_text, key, cipher_bytes, mod_plain_text_len, &cipher_bytes_len);
    else 
        cbc_encrypt(plain_text, key, iv, cipher_bytes, mod_plain_text_len, &cipher_bytes_len);

    total_blocks = cipher_bytes_len / 16;
    for(int i = 0; i < total_blocks; i++) {
        unsigned char current_block[16] = {0};
        memcpy(current_block, cipher_bytes + i * 16, 16);
        for(int j = 0; j < total_blocks; j++) {
            int counter = 0;
            unsigned char next_block[16] = {0};
            memcpy(next_block, cipher_bytes + j * 16, 16);
            
            if(i != j) {
                for(int k = 0; k < 16; k++){
                    if(current_block[k] == next_block[k])
                        counter++;
                }
            }
            if(counter == 16)
                ecb = true;
        }
    }
    ecb == true ? printf("Challenge 11 = ECB Encryption\n") : printf("Challenge 11 = CBC Encryption\n");
    return 1;
}

int main() {
    //challenge_9();
    //challenge_10();
    challenge_11();
    return 1;
}