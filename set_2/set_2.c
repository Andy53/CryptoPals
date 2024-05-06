#include <stdio.h>

#include "../PKCS7.h"

int challenge_9() {
    unsigned char message[] = "YELLOW SUBMARINE";
    PKCS7_Padding *padded   = addPadding(message, 16, 20);
    char *padded_message    = padded->dataWithPadding;

    printf("Challenge 9: YELLOW SUBMARINE with PCKS#7 padding = ");
    for(size_t i = 0; i < padded->dataLengthWithPadding; i++) {
        printf("\\x%02X", padded_message[i]);
    }
    printf("\n");

    return 0;
}

int main() {
    challenge_9();
    return 0;
}