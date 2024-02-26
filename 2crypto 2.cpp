#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

void encrypt(char plaintext[], char key[]) {
    int i;
    char ciphertext[strlen(plaintext)];

    for (i = 0; i < strlen(plaintext); i++) {
        if (isalpha(plaintext[i])) {
            if (islower(plaintext[i]))
                ciphertext[i] = tolower(key[plaintext[i] - 'a']);
            else
                ciphertext[i] = toupper(key[plaintext[i] - 'A']);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[i] = '\0';

    printf("Encrypted text: %s\n", ciphertext);
}

int main() {
    char plaintext[100];
    char key[ALPHABET_SIZE + 1];
    int i;

    printf("Enter the text to be encrypted: ");
    fgets(plaintext, sizeof(plaintext), stdin);

    printf("Enter the key (26 unique letters): ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0';

    if (strlen(key) != ALPHABET_SIZE) {
        printf("Error: Key must contain 26 unique letters.\n");
        return 1;
    }

    for (i = 0; i < ALPHABET_SIZE; i++) {
        if (!isalpha(key[i])) {
            printf("Error: Key must contain only alphabetic characters.\n");
            return 1;
        }
    }

    encrypt(plaintext, key);

    return 0;
}

