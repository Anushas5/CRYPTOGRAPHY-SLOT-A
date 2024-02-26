#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

void encrypt(char *plaintext, int *key, char *ciphertext) {
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        if (isalpha(plaintext[i])) {
            int shift = key[i] % ALPHABET_SIZE;
            if (isupper(plaintext[i])) {
                ciphertext[i] = ((plaintext[i] - 'A' + shift) % ALPHABET_SIZE) + 'A';
            } else {
                ciphertext[i] = ((plaintext[i] - 'a' + shift) % ALPHABET_SIZE) + 'a';
            }
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[len] = '\0';
}

void decrypt(char *ciphertext, int *key, char *plaintext) {
    int len = strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        if (isalpha(ciphertext[i])) {
            int shift = key[i] % ALPHABET_SIZE;
            if (isupper(ciphertext[i])) {
                plaintext[i] = (((ciphertext[i] - 'A' - shift) + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
            } else {
                plaintext[i] = (((ciphertext[i] - 'a' - shift) + ALPHABET_SIZE) % ALPHABET_SIZE) + 'a';
            }
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[len] = '\0';
}

void findKey(char *plaintext, char *ciphertext, int *key) {
    int len = strlen(plaintext);
    for (int i = 0; i < len; i++) {
        int shift = ((ciphertext[i] - plaintext[i]) + ALPHABET_SIZE) % ALPHABET_SIZE;
        key[i] = shift;
    }
}

int main() {
    char plaintext[] = "sendmoremoney";
    int key_stream[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    char ciphertext[strlen(plaintext) + 1];

    encrypt(plaintext, key_stream, ciphertext);
    printf("Encrypted ciphertext: %s\n", ciphertext);

    char given_ciphertext[] = "DRXXIYJETZFOD";

    int key[strlen(plaintext)];
    findKey(plaintext, given_ciphertext, key);

    char decrypted_plaintext[strlen(given_ciphertext) + 1];
    decrypt(given_ciphertext, key, decrypted_plaintext);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    return 0;
}

