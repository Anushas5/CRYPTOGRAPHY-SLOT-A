#include <stdio.h>
#include <string.h>
#include <ctype.h>

void generateCipherSequence(char *keyword, char *cipher) {
    int len = strlen(keyword);
    int i, j;

    strcpy(cipher, keyword);

    int used[26] = {0};
    for (i = 0; i < len; i++) {
        if (isalpha(keyword[i])) {
            used[toupper(keyword[i]) - 'A'] = 1;
        }
    }

    j = len;
    for (i = 0; i < 26; i++) {
        if (!used[i]) {
            cipher[j++] = 'A' + i;
        }
    }
    cipher[j] = '\0'; 
}

void encrypt(char *plaintext, char *cipher) {
    int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha(plaintext[i])) {
            if (islower(plaintext[i])) {
                printf("%c", tolower(cipher[plaintext[i] - 'a']));
            } else {
                printf("%c", toupper(cipher[plaintext[i] - 'A']));
            }
        } else {
            printf("%c", plaintext[i]); 
        }
    }
}

int main() {
    char keyword[] = "CIPHER";
    char cipher[27];

    generateCipherSequence(keyword, cipher);

    printf("Generated Cipher Sequence: %s\n", cipher);

    char plaintext[] = "HELLO WORLD!";
    printf("Plaintext: %s\n", plaintext);
    printf("Encrypted Message: ");
    encrypt(plaintext, cipher);
    printf("\n");

    return 0;
}

