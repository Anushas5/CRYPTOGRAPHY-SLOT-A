#include <stdio.h>l
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

const float english_freq[ALPHABET_SIZE] = {
    0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, // A-G
    0.0609, 0.0697, 0.0015, 0.0077, 0.0402, 0.0241, 0.0675, // H-N
    0.0751, 0.0193, 0.0009, 0.0599, 0.0633, 0.0906, 0.0276, // O-U
    0.0098, 0.0236, 0.0015, 0.0197, 0.0007                  // V-Z
};
void calculate_frequency(const char *text, int *frequency) {
    for (const char *ptr = text; *ptr; ptr++) {
        if (isalpha(*ptr)) {
            frequency[tolower(*ptr) - 'a']++;
        }
    }
}

// Function to decrypt ciphertext based on key
void decrypt(const char *ciphertext, const char *key) {
    printf("Potential plaintext using key '%s': ", key);
    for (const char *ptr = ciphertext; *ptr; ptr++) {
        if (isalpha(*ptr)) {
            char decrypted = *ptr;
            if (isupper(*ptr)) {
                decrypted = toupper(key[tolower(*ptr) - 'a']);
            } else {
                decrypted = key[*ptr - 'a'];
            }
            printf("%c", decrypted);
        } else {
            printf("%c", *ptr);
        }
    }
    printf("\n");
}

// Function to compare frequency with English letter frequency
float compare_frequency(const int *frequency) {
    float score = 0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        score += (float)frequency[i] * english_freq[i];
    }
    return score;
}

// Function to perform letter frequency attack
void letter_frequency_attack(const char *ciphertext, int top) {
    int frequency[ALPHABET_SIZE] = {0};
    calculate_frequency(ciphertext, frequency);

    // Generate all possible keys
    char key[ALPHABET_SIZE + 1];
    key[ALPHABET_SIZE] = '\0';
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        key[i] = 'a' + i;
    }

    // Sort keys based on score
    for (int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (int j = i + 1; j < ALPHABET_SIZE; j++) {
            // Swap key and frequency if score is higher
            if (compare_frequency(frequency) < compare_frequency(frequency)) {
                int temp_freq = frequency[i];
                frequency[i] = frequency[j];
                frequency[j] = temp_freq;
                char temp_key = key[i];
                key[i] = key[j];
                key[j] = temp_key;
            }
        }
    }

    // Print top potential plaintexts
    for (int i = 0; i < top; i++) {
        decrypt(ciphertext, key);
    }
}

int main() {
    const char *ciphertext = "Enter your ciphertext here";
    int top = 10; // Change this value to get more or fewer potential plaintexts
    letter_frequency_attack(ciphertext, top);
    return 0;
}

