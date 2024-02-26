#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

void encrypt(int a, int b, char plaintext[]) {
    int i;
    char ciphertext[strlen(plaintext)];

    for (i = 0; i < strlen(plaintext); i++) {
        if (isalpha(plaintext[i])) {
            char base;
            if (islower(plaintext[i]))
                base = 'a';
            else
                base = 'A';

            
            ciphertext[i] = ((a * (plaintext[i] - base)) + b) % 26 + base;
            if (ciphertext[i] < base)
                ciphertext[i] += 26; 
        } else {
            ciphertext[i] = plaintext[i]; 
        }
    }
    ciphertext[i] = '\0';

    printf("Encrypted text: %s\n", ciphertext);
}

int isCoprime(int a, int b) {
    int temp;
    while (b != 0) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a == 1;
}

// Function to find allowed values of a
void findAllowedValuesOfA() {
    printf("Allowed values of a: ");
    for (int a = 1; a < 26; a++) {
        if (isCoprime(a, 26)) {
            printf("%d ", a);
        }
    }
    printf("\n");
}

int main() {
    char plaintext[100];
    int a, b;
    printf("Enter the text to be encrypted: ");
    fgets(plaintext, sizeof(plaintext), stdin);

    printf("Enter the value of a: ");
    scanf("%d", &a);

    
    if (!isCoprime(a, 26)) {
        printf("Error: Value of a is not allowed.\n");
        findAllowedValuesOfA();
        return 1;
    }

    // Input value of b
    printf("Enter the value of b (0-25): ");
    scanf("%d", &b);

    // Validate value of b
    if (b < 0 || b >= 26) {
        printf("Error: Value of b is not allowed.\n");
        return 1;
    }

    // Encrypt using affine Caesar cipher
    encrypt(a, b, plaintext);

    return 0;
}

