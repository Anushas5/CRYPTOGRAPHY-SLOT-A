#include <stdio.h>
#include <string.h>
#include <ctype.h>
void removeNonAlphabetic(char *text) {
    int len = strlen(text);
    int index = 0;
    for (int i = 0; i < len; i++) {
        if (isalpha(text[i])) {
            text[index++] = toupper(text[i]);
        }
    }
    text[index] = '\0'; 
}
void decryptPlayfair(char *text, char key[][5]) {
    int len = strlen(text);
    for (int i = 0; i < len; i += 2) {
        char a = text[i];
        char b = text[i + 1];
        int row_a, col_a, row_b, col_b;
        for (int row = 0; row < 5; row++) {
            for (int col = 0; col < 5; col++) {
                if (key[row][col] == a) {
                    row_a = row;
                    col_a = col;
                }
                if (key[row][col] == b) {
                    row_b = row;
                    col_b = col;
                }
            }
        }
        if (row_a == row_b) { 
            printf("%c%c", key[row_a][(col_a - 1 + 5) % 5], key[row_b][(col_b - 1 + 5) % 5]);
        } else if (col_a == col_b) { 
            printf("%c%c", key[(row_a - 1 + 5) % 5][col_a], key[(row_b - 1 + 5) % 5][col_b]);
        } else { 
            printf("%c%c", key[row_a][col_b], key[row_b][col_a]);
        }
    }
}

int main() {
    char text[] = "KXJEY UREBE ZWEHE WRYTU HEYFS KREHE GOYFI WTTTU OLKSY CAJPO BOTEI ZONTX BYBNT GONEY CUZWR GDSON SXBOU YWRHE BAAHY USEDQ";
    char key[5][5] = {
        {'A', 'B', 'C', 'D', 'E'},
        {'F', 'G', 'H', 'I', 'K'},
        {'L', 'M', 'N', 'O', 'P'},
        {'Q', 'R', 'S', 'T', 'U'},
        {'V', 'W', 'X', 'Y', 'Z'}
    };

    removeNonAlphabetic(text);

    printf("Decrypted Message:\n");
    decryptPlayfair(text, key);
    printf("\n");

    return 0;
}

