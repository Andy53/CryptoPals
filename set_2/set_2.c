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

int challenge_12() {
    int block_size          = 0;
    unsigned char key[16]   = {0};
    unsigned char *b64_text = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                              "YnkK";
    
    int plain_bytes_len = 0;
    b64_decode(b64_text, NULL, &plain_bytes_len);
    unsigned char plain_bytes[plain_bytes_len];
    unsigned char decrypted_bytes[plain_bytes_len];
    b64_decode(b64_text, plain_bytes, &plain_bytes_len);

    for(int i = 0; i < plain_bytes_len; i++)
        decrypted_bytes[i] = 0;

    int cipher_bytes_len = 0;
    ecb_encrypt(plain_bytes, key, NULL, plain_bytes_len, &cipher_bytes_len);
    unsigned char cipher_bytes[cipher_bytes_len];
    ecb_encrypt(plain_bytes, key, cipher_bytes, plain_bytes_len, &cipher_bytes_len);

    srand ( time(NULL) );
    for(int i = 0; i < 16; i++)
        key[i] = rand();

    // Find block size of encryption algorithm.
    int buffer_counter = 0;
    while(block_size == 0) {
        int buffer_len = plain_bytes_len + ++buffer_counter;
        int cipher_len = 0;
        unsigned char buffer[buffer_len];

        for(int i = 0; i < buffer_counter; i++) 
            buffer[i] == 'A';

        ecb_encrypt(buffer, key, NULL, buffer_len, &cipher_len);
        if(buffer_len == cipher_len) {
            if(buffer_len % 64 == 0) 
                block_size = 64;
            else if(buffer_len % 32 == 0) 
                block_size = 32;
            else if(buffer_len % 16 == 0) 
                block_size = 16;
        }
    }

    // Identify plaintext byte by byte.
    for(int i = 0; i < cipher_bytes_len; i++) {
        int mod_plain_bytes_len = plain_bytes_len + (16 - (i % 16));
        int padding = mod_plain_bytes_len - plain_bytes_len;
        unsigned char mod_plain_bytes[mod_plain_bytes_len];
        unsigned char new_plain_bytes[mod_plain_bytes_len];

        for(int j = 0; j < 255; j++) {
            for(int k = 0; k < mod_plain_bytes_len; k++) {
                if(k < padding) {
                    mod_plain_bytes[k] = 'A';
                    new_plain_bytes[k] = 'A';
                } else if(k >= padding && k < (padding + i)) {
                    mod_plain_bytes[k] = plain_bytes[k - padding];
                    new_plain_bytes[k] = plain_bytes[k - padding];
                } else if(k == (padding + i)) {
                    mod_plain_bytes[k] = plain_bytes[k - padding];
                    new_plain_bytes[k] = j;
                } else {
                    mod_plain_bytes[k] = plain_bytes[k - padding];
                    new_plain_bytes[k] = plain_bytes[k - padding];
                } 
            }

            int mod_cipher_bytes_len = 0;
            ecb_encrypt(mod_plain_bytes, key, NULL, mod_plain_bytes_len, &mod_cipher_bytes_len);
            unsigned char mod_cipher_bytes[mod_cipher_bytes_len];
            unsigned char new_cipher_bytes[mod_cipher_bytes_len];
            ecb_encrypt(mod_plain_bytes, key, mod_cipher_bytes, mod_plain_bytes_len, &mod_cipher_bytes_len);
            ecb_encrypt(new_plain_bytes, key, new_cipher_bytes, mod_plain_bytes_len, &mod_cipher_bytes_len);

            bool match = true;
            for(int k = 0; k < mod_cipher_bytes_len; k++) {
                if(mod_cipher_bytes[k] != new_cipher_bytes[k])
                    match = false;
            }

            if(match == true) {
                decrypted_bytes[i] = j;
            }
        }
    }
    

    printf("Challenge 12 = ");
    for(int i = 0; i < plain_bytes_len; i++)
        printf("%c", decrypted_bytes[i]);
    printf("\n");
    return 1;
}

int challenge_13_oracle(unsigned char *input, unsigned char *cipher_bytes, int *cipher_bytes_len, unsigned char *key) {
    int valid_len = strlen(input);
    for(int i = 0; i < strlen(input); i++) {
        if(input[i] == '&' || input[i] == '=')
            valid_len = i - 1;
    }

    char email[valid_len];
    for(int i = 0; i < valid_len; i++) 
        email[i] = input[i]; 

    char user_string[24 + valid_len];
    memcpy(user_string, "email=", 6);
    memcpy(user_string + 6, email, strlen(email));
    memcpy(user_string + 5 + strlen(email), "&uid=10&role=user\0", 18);
    
    int length = 0;
    ecb_encrypt(user_string, key, NULL, strlen(user_string), &length);
    
    if(*cipher_bytes_len != length) {
        *cipher_bytes_len = length;
        return 2;
    }

    ecb_encrypt(user_string, key, cipher_bytes, strlen(user_string), cipher_bytes_len);

    return 1;
}

int challenge_13() {
    unsigned char key[16] = {0};
    srand ( time(NULL) );
    for(int i = 0; i < 16; i++)
        key[i] = rand();

    // String to manipulate: email=foo@bar.com&uid=10&role=user 

    int cipher_bytes_len = 0;
    unsigned char email[45] = {0};
    unsigned char block[16] = {0};

    block[0] = 'a';
    block[1] = 'd';
    block[2] = 'm';
    block[3] = 'i';
    block[4] = 'n';

    PKCS7_Padding *padded   = addPadding(block, 5, 16);
    char *padded_message    = padded->dataWithPadding;

    for(int i = 0; i < 45; i++){
        if(i < 26)
            email[i] = 'A';
        else if(i >= 26 && i < 42)
            email[i] = padded_message[i - 26];
        else if(i >= 45)
            email[i] = 'A';
    }
        

    challenge_13_oracle(email, NULL, &cipher_bytes_len, key);
    unsigned char cipher_bytes[cipher_bytes_len];
    challenge_13_oracle(email, cipher_bytes, &cipher_bytes_len, key);

    unsigned char mod_cipher_bytes[cipher_bytes_len];
    for(int i = 0; i < cipher_bytes_len; i++){
        if(i < 32)
            mod_cipher_bytes[i] = cipher_bytes[i];
        else if(i >= 32 && i < 48)
            mod_cipher_bytes[i] = cipher_bytes[i - 16];
        else if(i >= 48 && i < 64)
            mod_cipher_bytes[i] = cipher_bytes[i];
        else if(i >= 64)
            mod_cipher_bytes[i] = cipher_bytes[i - 32];
    }

    int plain_bytes_len = 0;
    unsigned char plain_bytes[cipher_bytes_len];
    ecb_decrypt(mod_cipher_bytes, key, plain_bytes, cipher_bytes_len, &plain_bytes_len);

    printf("email       = ");
    for(int i = 0; i < plain_bytes_len; i++)
        printf("%c", plain_bytes[i]);
        //printf("\\x%02x", plain_bytes[i]);
    printf("\n");

    printf("plain_bytes = ");
    for(int i = 0; i < 29; i++)
        printf("%c", email[i]);
        //printf("\\x%02x", plain_bytes[i]);
    printf("\n");

    PKCS7_unPadding *unPadded   = removePadding(plain_bytes, cipher_bytes_len);
    char *unPadded_message    = unPadded->dataWithoutPadding;

    printf("Challenge_13 = ");
    for(int i = 0; i < unPadded->dataLengthWithoutPadding; i++)
        printf("%c", unPadded_message[i]);
    printf("\n");
    
    return 1;
}

int challenge_14() {
    unsigned char key[16] = {0};
    srand ( time(NULL) );
    for(int i = 0; i < 16; i++)
        key[i] = rand();

    int random_bytes_len = rand() % 16 + 1;
    unsigned char randon_bytes[random_bytes_len];
    for(int i = 0; i < random_bytes_len; i++)
        randon_bytes[i] = rand();

    unsigned char *target_bytes = "target bytes successfully decrypted!";
    unsigned char plain_bytes[36] = {0};
    int cipher_bytes_len = 0;
    int bytes_to_append  = 0;

    // Find size of appended bytes.
    for(int i = 0; i < 16; i++) {
        int bytes_len = i + 32 + random_bytes_len + 36;
        unsigned char bytes[bytes_len];
        for(int j = 0; j < bytes_len; j++) {
            if(j < random_bytes_len)
                bytes[j] = randon_bytes[j];
            else if(j < i + 32 + random_bytes_len)
                bytes[j] = 'A';
            else
                bytes[j] = target_bytes[j - (i + random_bytes_len + 32)];
        }

        ecb_encrypt(bytes, key, NULL, bytes_len, &cipher_bytes_len);
        unsigned char cipher_bytes[cipher_bytes_len];
        ecb_encrypt(bytes, key, cipher_bytes, bytes_len, &cipher_bytes_len);

        int counter = 0;
        for(int j = 0; j < cipher_bytes_len; j += 16) {
            bool match = true;
            for(int k = 0; k < 16; k++) {
                if(cipher_bytes[k + j] != cipher_bytes[k + j + 16] && match == true)
                    match = false;
            }
            if(match == true)
                counter++;
        }
        if(counter > 0) {
            bytes_to_append = i;
            i = 16;
        }
    }
    unsigned char decrypted_bytes[strlen(target_bytes)];
    
    // Identify plaintext byte by byte.
    for(int i = 0; i < cipher_bytes_len; i++) {
        int mod_plain_bytes_len = bytes_to_append + 16 + strlen(target_bytes) + (16 - (i % 16));
        int padding = mod_plain_bytes_len - strlen(target_bytes);
        unsigned char mod_plain_bytes[mod_plain_bytes_len];
        unsigned char new_plain_bytes[mod_plain_bytes_len];

        for(int j = 0; j < 255; j++) {
            for(int k = 0; k < mod_plain_bytes_len; k++) {
                if(k < padding) {
                    mod_plain_bytes[k] = 'A';
                    new_plain_bytes[k] = 'A';
                } else if(k >= padding && k < (padding + i)) {
                    mod_plain_bytes[k] = target_bytes[k - padding];
                    new_plain_bytes[k] = target_bytes[k - padding];
                } else if(k == (padding + i)) {
                    mod_plain_bytes[k] = target_bytes[k - padding];
                    new_plain_bytes[k] = j;
                } else {
                    mod_plain_bytes[k] = target_bytes[k - padding];
                    new_plain_bytes[k] = target_bytes[k - padding];
                } 
            }

            int mod_cipher_bytes_len = 0;
            ecb_encrypt(mod_plain_bytes, key, NULL, mod_plain_bytes_len, &mod_cipher_bytes_len);
            unsigned char mod_cipher_bytes[mod_cipher_bytes_len];
            unsigned char new_cipher_bytes[mod_cipher_bytes_len];
            ecb_encrypt(mod_plain_bytes, key, mod_cipher_bytes, mod_plain_bytes_len, &mod_cipher_bytes_len);
            ecb_encrypt(new_plain_bytes, key, new_cipher_bytes, mod_plain_bytes_len, &mod_cipher_bytes_len);

            bool match = true;
            for(int k = 0; k < mod_cipher_bytes_len; k++) {
                if(mod_cipher_bytes[k] != new_cipher_bytes[k])
                    match = false;
            }

            if(match == true) {
                decrypted_bytes[i] = j;
            }
        }
    }
    

    printf("Challenge 14 = ");
    for(int i = 0; i < strlen(target_bytes); i++)
        printf("%c", decrypted_bytes[i]);
    printf("\n");
    return 1;
}

int challenge_15() {
    unsigned char *bytes_1 = "ICE ICE BABY\x04\x04\x04\x04";
    unsigned char *bytes_2 = "ICE ICE BABY\x05\x05\x05\x05";
    unsigned char *bytes_3 = "ICE ICE BABY\x01\x02\x03\x04";

    printf("Challenge 15:\n");
    printf("    bytes_1 padding = "); 
    validatePadding(bytes_1, 16) ? printf("true\n") : printf("false\n");
    printf("    bytes_2 padding = "); 
    validatePadding(bytes_2, 16) ? printf("true\n") : printf("false\n");
    printf("    bytes_3 padding = "); 
    validatePadding(bytes_3, 16) ? printf("true\n") : printf("false\n");
    return 1;
}

int challenge_16() {
    unsigned char iv[16] = {0};
    unsigned char key[16] = {0};
    srand ( time(NULL) );
    for(int i = 0; i < 16; i++)
        key[i] = rand();

    unsigned char *prepend = "comment1=cooking%20MCs;userdata="; // length 32
    unsigned char *u_data  = ":admin<true";                        // length 10
    unsigned char *append  = ";comment2= like a pound of bacon";  // length 32

    int plain_text_len = strlen(prepend) + strlen(u_data) + strlen(append);
    unsigned char plain_text[plain_text_len];

    for(int i = 0; i < plain_text_len; i++) {
        if(i < strlen(prepend))
            plain_text[i] = prepend[i];
        else if(i >= strlen(prepend) && i < strlen(prepend) + strlen(u_data))
            plain_text[i] = u_data[i - strlen(prepend)];
        else {
            plain_text[i] = append[i - (strlen(prepend) + strlen(u_data))];
        }
    }

    int cipher_text_len = 0;
    cbc_encrypt(plain_text, key, iv, NULL, plain_text_len, &cipher_text_len);
    unsigned char cipher_text[cipher_text_len];
    cbc_encrypt(plain_text, key, iv, cipher_text, plain_text_len, &cipher_text_len);

    cipher_text[16] = cipher_text[16] ^ 0x01;
    cipher_text[22] = cipher_text[22] ^ 0x01;

    int plain_bytes_len = 0;
    cbc_decrypt(cipher_text, key, iv, NULL, cipher_text_len, &plain_bytes_len);
    unsigned char plain_bytes[plain_bytes_len];
    cbc_decrypt(cipher_text, key, iv, plain_bytes, cipher_text_len, &plain_bytes_len);

    
    printf("Challenge 16 = \nplain_text = ");
    for(int i = 0; i < plain_text_len; i++) {
        printf("%c", plain_text[i]);
    }
    printf("\nafter bit flip = ");
    
    for(int i = 0; i < plain_bytes_len; i++) {
        printf("%c", plain_bytes[i]);
    }
    printf("\n");
    
    
    return 1;
}

int main() {
    challenge_9();
    challenge_10();
    challenge_11();
    challenge_12();
    challenge_13();
    challenge_14();
    challenge_15();
    challenge_16();
    return 1;
}