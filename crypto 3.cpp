#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

void preprocessKey(char *key) {
    int i, j, len = strlen(key);
    char temp[len];
    int index = 0;

    for (i = 0; i < len; i++) {
        if (key[i] != ' ') {
            temp[index++] = tolower(key[i]);
        }
    }
    temp[index] = '\0';

    index = 0;
    for (i = 0; i < strlen(temp); i++) {
        int found = 0;
        for (j = 0; j < index; j++) {
            if (temp[i] == temp[j]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            key[index++] = temp[i];
        }
    }
    key[index] = '\0';
}

void generateKeyTable(char key[], char keyTable[SIZE][SIZE]) {
    int i, j, k = 0;
    char alphabet[26] = "abcdefghiklmnopqrstuvwxyz"; 

    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            if (k < strlen(key)) {
                keyTable[i][j] = key[k++];
            } else {
                int found = 0;
                while (alphabet[j]) {
                    if (alphabet[j] != 'j') {
                        keyTable[i][j] = alphabet[j++];
                        found = 1;
                        break;
                    }
                    j++;
                }
                if (!found)
                    keyTable[i][j] = '\0';
            }
        }
    }
}

void findPositions(char keyTable[SIZE][SIZE], char a, char b, int *row1, int *col1, int *row2, int *col2) {
    int i, j;

    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            if (keyTable[i][j] == a) {
                *row1 = i;
                *col1 = j;
            }
            if (keyTable[i][j] == b) {
                *row2 = i;
                *col2 = j;
            }
        }
    }
}

void encrypt(char keyTable[SIZE][SIZE], char msg[]) {
    int i, row1, col1, row2, col2;

    for (i = 0; i < strlen(msg); i++) {
        if (msg[i] == 'j') 
            msg[i] = 'i';
        else if (msg[i] == 'J')
            msg[i] = 'I';
        else
            msg[i] = tolower(msg[i]);
    }

    for (i = 0; i < strlen(msg); i += 2) {
        findPositions(keyTable, msg[i], msg[i + 1], &row1, &col1, &row2, &col2);

        if (row1 == row2) {
            msg[i] = keyTable[row1][(col1 + 1) % SIZE];
            msg[i + 1] = keyTable[row2][(col2 + 1) % SIZE];
        }
        
        else if (col1 == col2) {
            msg[i] = keyTable[(row1 + 1) % SIZE][col1];
            msg[i + 1] = keyTable[(row2 + 1) % SIZE][col2];
        }
        
        else {
            msg[i] = keyTable[row1][col2];
            msg[i + 1] = keyTable[row2][col1];
        }
    }

    printf("Encrypted Message: %s\n", msg);
}

int main() {
    char key[100], msg[100], keyTable[SIZE][SIZE];

    printf("Enter the key: ");
    fgets(key, sizeof(key), stdin);

    printf("Enter the message: ");
    fgets(msg, sizeof(msg), stdin);

    key[strcspn(key, "\n")] = '\0';
    msg[strcspn(msg, "\n")] = '\0';

    preprocessKey(key);

    generateKeyTable(key, keyTable);

    encrypt(keyTable, msg);

    return 0;
}

