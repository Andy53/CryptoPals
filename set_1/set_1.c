#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "../crypto_helpers.h"
#include "../List.h"

int challenge_1() {
    unsigned char hex[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    unsigned char bytes[48] = {0};
    int bytes_len = 0;

    hex_encode(hex, bytes, &bytes_len);

    unsigned char *base64 = b64_encode(bytes, bytes_len);
    printf("challenge 1 out  = %s\n", base64);
    return 1;
}

int challenge_2() {
    unsigned char hex_1[] = "1c0111001f010100061a024b53535009181c";
    unsigned char hex_2[] = "686974207468652062756c6c277320657965";
    unsigned char bytes_1[18] = {0}; 
    unsigned char bytes_2[18] = {0}; 
    unsigned char bytes_3[18] = {0}; 
    int bytes_1_len = 0;
    int bytes_2_len = 0;

    hex_encode(hex_1, bytes_1, &bytes_1_len);
    hex_encode(hex_2, bytes_2, &bytes_2_len);
    xor(bytes_1, bytes_2, bytes_3, bytes_1_len, bytes_2_len);
    
    printf("challenge 2 out  = ");
    for(int i = 0; i < 18; i++) {
        printf("%02X", bytes_3[i]);
    }
    printf("\n");
    return 1;
}

int challenge_3() {
    unsigned char letters[]   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 :\n"; 
    unsigned char hex[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char bytes[34]; 
    unsigned char plain[34];
    int bytes_len = 34;

    int score      = 0;
    unsigned char key = '!';
    hex_encode(hex, bytes, &bytes_len);

    for(int i = 0; i < strlen((const char *)letters); i++){
        unsigned char out_bytes[bytes_len];
        int char_score = 0;
        xor(bytes, &letters[i], out_bytes, bytes_len, 1);
        
        for(int j = 0; j < bytes_len; j++) {
            if(out_bytes[j] == 'e' || out_bytes[j] == 't' || out_bytes[j] == 'a' || out_bytes[j] == 'o' || out_bytes[j] == 'i' 
                || out_bytes[j] == 'n' || out_bytes[j] == 's' || out_bytes[j] == 'r' || out_bytes[j] == 'h') {
                        char_score++;
            }
            if(char_score > score) {
                score = char_score;
                key = letters[i];
            }
        }
    }
    xor(bytes, &key, plain, bytes_len, 1);
    printf("Challenge 3 key  = %c Message = ", key);
    for(int i = 0; i < bytes_len; i++){
        printf("%c", plain[i]);
    }
    printf("\n");
    return 1;
}

int challenge_4() {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    unsigned char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 :\n";
    unsigned char plain[30];
    unsigned char bytes[30];
    int bytes_len = 30;
    int score = 0;
    unsigned char key = '!';

    fp = fopen("challenge_4_inputs.txt", "r");
    if (fp == NULL)
        return 2;

    while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\n")] = 0;
        

        hex_encode((unsigned char *)line, bytes, &bytes_len);
        for(int i = 0; i < strlen((const char *)letters); i++){
            unsigned char out_bytes[bytes_len];
            int char_score = 0;
            xor(bytes, &letters[i], out_bytes, bytes_len, 1);
            
            for(int j = 0; j < bytes_len; j++) {
                if(out_bytes[j] == 'e' || out_bytes[j] == 't' || out_bytes[j] == 'a' || out_bytes[j] == 'o' || out_bytes[j] == 'i' 
                    || out_bytes[j] == 'n' || out_bytes[j] == 's' || out_bytes[j] == 'r' || out_bytes[j] == 'h') {
                            char_score++;
                }
                if(char_score > score) {
                    score = char_score;
                    key = letters[i];
                    for(int i = 0; i < bytes_len; i++){
                        plain[i] = out_bytes[i];
                    }
                }
            }
        }
    }

    fclose(fp);
    if (line)
        free(line);

    printf("Challenge 4 key  = %c Message = ", key);
    for(int i = 0; i < bytes_len; i++){
        printf("%c", plain[i]);
    }
    return 1;
}

int challenge_5() {
    unsigned char bytes_1[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    unsigned char bytes_2[] = "ICE";
    unsigned char bytes_3[74] = {0};

    xor(bytes_1, bytes_2, bytes_3, strlen((const char *)bytes_1), strlen((const char *)bytes_2));
    printf("challenge 5 out  = ");
    for(int i = 0; i < 74; i++) {
        printf("%02x", bytes_3[i]);
    }
    printf("\n");

    return 1;
}

int challenge_6() {
    FILE *fp                         = fopen("challenge_5_inputs.txt", "r");
    char *cipher_text                = NULL;
    int cipher_text_len           = 0;
    int cipher_bytes_len          = 2875;
    int keysize                   = 0;
    float key_edit_dist              = 100.0;
    unsigned char cipher_bytes[2875] = {0};
    unsigned char plain_bytes[2875]  = {0};


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

    b64_decode(cipher_text, cipher_bytes, &cipher_bytes_len);
    for(int i = 2; i < 40; i++) {
        float average_edit = 0.0;
        for(int j = 0; j < ((2875 / i) - 1); j++){
            float result = 0.0;
            int edit_dist = 0;
            unsigned char *current_position = cipher_bytes + (j * i);
        
            unsigned char key_bytes_1[i];
            unsigned char key_bytes_2[i]; 
            unsigned char key_bytes_3[i];
            unsigned char key_bytes_4[i]; 

            memcpy(key_bytes_1, current_position, i);
            memcpy(key_bytes_2, current_position + i, i);
            memcpy(key_bytes_3, current_position + (i * 2), i);
            memcpy(key_bytes_4, current_position + (i * 3), i);

            edit_distance(key_bytes_1, key_bytes_2, i, &edit_dist);
            result = (float)edit_dist;
            edit_distance(key_bytes_3, key_bytes_4, i, &edit_dist);
            result += (float)edit_dist ;
            result = (result / 2) / i;
            average_edit += result;
        }
        average_edit = average_edit / (2875 / i);
        if (average_edit < key_edit_dist) {
            key_edit_dist = average_edit;
            keysize = i;
        }
    }

    unsigned char keysize_blocks[keysize][2875 / keysize];

    for(int i = 0; i < keysize; i++) {
        for(int j = 0; j < (2875 / keysize); j++){
            keysize_blocks[i][j] = cipher_bytes[i + (j * keysize)];
        }
    }

    unsigned char letters[]   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 :\n"; 
    unsigned char key[keysize];

    for(int i = 0; i < keysize; i++) {
        unsigned char slice_bytes[2875 / keysize];
        unsigned char out_bytes[2875 / keysize];
        int bytes_len = 2875 / keysize;
        int score = 0;

        for (int a = 0; a < (2875 / keysize); a++){
            slice_bytes[a] = keysize_blocks[i][a];
        }

        for(int j = 0; j < 64; j++){
            int char_score = 0;
            int spaces = 0;
            xor(slice_bytes, &letters[j], out_bytes, 2875 / keysize, 1);

            for (int k = 0; k < (2875 / keysize); k++){
                if(out_bytes[k] == ' ') {
                    char_score++;
                }
                if(out_bytes[k] == 'e' || out_bytes[k] == 't' || out_bytes[k] == 'a' || out_bytes[k] == 'o' || out_bytes[k] == 'i' || out_bytes[k] == 'n' || out_bytes[k] == 's' || out_bytes[k] == 'r' || out_bytes[k] == 'h') {
                    char_score++;
                }
                else if(out_bytes[k] == '\n') {
                    char_score++;
                }
            }
            if(char_score > score) {
                score = char_score;
                key[i] = letters[j];
            }
        }
    }

    printf("Challenge 6 Key  = %s\n", key);
    xor(cipher_bytes, key, plain_bytes, 2875, keysize);
    free(cipher_text);
    return 1;
}

int challenge_7() {
    FILE *fp                   = fopen("challenge_7_inputs.txt", "r");
    unsigned char *cipher_text = NULL;
    unsigned char *key         = "YELLOW SUBMARINE";
    int cipher_text_len     = 0;
    int cipher_bytes_len    = 0;

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

    EVP_CIPHER_CTX *ctx;

    int len;
    unsigned char plain[3840];

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 5;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        return 6;

    if(1 != EVP_DecryptUpdate(ctx, plain, &len, cipher_bytes, cipher_bytes_len))
        return 7;
    
    int plain_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plain + plain_len, &len))
        return 8;

    for(int i = 0; i < plain_len; i++){
        printf("%c", plain[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int challenge_8() {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    unsigned char plain[30];
    unsigned char bytes[160];
    int bytes_len = 0;
    int score = 0;
    int line_num = 0;
    int counter = 0;

    fp = fopen("challenge_8_inputs.txt", "r");
    if (fp == NULL)
        return 2;

    while ((read = getline(&line, &len, fp)) != -1) {
        int line_score = 0;
        
        unsigned char blocks[10][16];
        line[strcspn(line, "\n")] = 0;

        hex_encode((unsigned char *)line, bytes, &bytes_len);

        for(int i = 0; i < bytes_len / 16; i++){
            memcpy(&blocks[i][0], bytes + (i * 16), 16);
        }

        for(int i = 0; i < 10; i++) {
            for(int j = 0; j < 10; j++) {
                bool match = true;
                if(i != j) {
                    for(int k = 0; k < 16 && match == true; k++) {
                        if(blocks[i][k] != blocks[j][k])
                            match = false;
                    }
                    if(match == true)
                        line_score++;
                }
            }
        }
        if(line_score > score){
            score = line_score;
            line_num = counter;
        }
        counter++;
    }
    printf("Challenge 8 ECB line = %d\n", line_num);
    return 1;
}

int main() {
    challenge_1();
    challenge_2();
    challenge_3();
    challenge_4();
    challenge_5();
    challenge_6();
    challenge_7();
    challenge_8();
    return 0;
}

