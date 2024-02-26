#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26

int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

int modInverse(int a, int m) {
    for (int x = 1; x < m; x++)
        if (((a % m) * (x % m)) % m == 1)
            return x;
    return -1;
}

void decrypt(char* ciphertext, int a, int b) {
    int mmi = modInverse(a, ALPHABET_SIZE);
    int len = strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            int x = (mmi * ((ciphertext[i] - 'A' - b + ALPHABET_SIZE) % ALPHABET_SIZE)) % ALPHABET_SIZE;
            printf("%c", (char)(x + 'A'));
        } else {
            printf("%c", ciphertext[i]);
        }
    }
}

int main() {
    char ciphertext[1000];
    printf("Enter the ciphertext: ");
    fgets(ciphertext, sizeof(ciphertext), stdin);

    int freq[ALPHABET_SIZE] = {0};
    int maxFreq = 0, secondMaxFreq = 0;
    char maxChar, secondMaxChar;

    int len = strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            freq[ciphertext[i] - 'A']++;
            if (freq[ciphertext[i] - 'A'] > maxFreq) {
                secondMaxFreq = maxFreq;
                secondMaxChar = maxChar;
                maxFreq = freq[ciphertext[i] - 'A'];
                maxChar = ciphertext[i];
            } else if (freq[ciphertext[i] - 'A'] > secondMaxFreq) {
                secondMaxFreq = freq[ciphertext[i] - 'A'];
                secondMaxChar = ciphertext[i];
            }
        }
    }

    int keyB = (secondMaxChar - 'A' - ('U' - 'A')) % ALPHABET_SIZE;
    if (keyB < 0)
        keyB += ALPHABET_SIZE;

    for (int a = 1; a < ALPHABET_SIZE; a++) {
        if (gcd(a, ALPHABET_SIZE) == 1) {
            int mmi = modInverse(a, ALPHABET_SIZE);
            if ((mmi * (maxChar - 'A' - keyB + ALPHABET_SIZE)) % ALPHABET_SIZE == ('B' - 'A')) {
                printf("Possible keys found: a = %d, b = %d\n", a, keyB);
                printf("Decrypted Message:\n");
                decrypt(ciphertext, a, keyB);
                printf("\n");
            }
        }
    }

    return 0;
}

