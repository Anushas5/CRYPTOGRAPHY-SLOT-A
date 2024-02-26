#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

// Key for 3DES (24 bytes, 192 bits)
unsigned char key[24] = "MYSECRETKEY12345678901234";

// IV (Initialization Vector)
unsigned char iv[8] = "INITVEC";

// Encrypt using 3DES in CBC mode
void encrypt3DESCBC(unsigned char *input, unsigned char *output, int input_length, unsigned char *key, unsigned char *iv) {
    DES_cblock iv_schedule;
    DES_key_schedule schedule1, schedule2, schedule3;

    DES_set_key_unchecked((DES_cblock *)key, &schedule1);
    DES_set_key_unchecked((DES_cblock *)(key + 8), &schedule2);
    DES_set_key_unchecked((DES_cblock *)(key + 16), &schedule3);

    memcpy(iv_schedule, iv, 8);

    for (int i = 0; i < input_length; i += 8) {
        DES_ncbc_encrypt(input + i, output + i, 8, &schedule1, &iv_schedule, DES_ENCRYPT);
        DES_ncbc_encrypt(output + i, output + i, 8, &schedule2, &iv_schedule, DES_DECRYPT);
        DES_ncbc_encrypt(output + i, output + i, 8, &schedule3, &iv_schedule, DES_ENCRYPT);
    }
}

int main() {
    unsigned char plaintext[] = "PLAINTEXT1234567890"; // Replace with your plaintext
    int input_length = strlen((char *)plaintext);
    unsigned char ciphertext[input_length];
    
    // Encrypt using 3DES in CBC mode
    encrypt3DESCBC(plaintext, ciphertext, input_length, key, iv);

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for (int i = 0; i < input_length; i++) {
        printf("%02X ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
