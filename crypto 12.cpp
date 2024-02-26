 #include <stdio.h>

void matrixMultiplication(int key[2][2], int message[2][20], int result[2][20]) {
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 20; j++) {
            result[i][j] = 0;
            for (int k = 0; k < 2; k++) {
                result[i][j] += key[i][k] * message[k][j];
            }
            result[i][j] %= 26; 
        }
    }
}

int main() {
    int key[2][2] = {{9, 4}, {5, 7}};
    int message[2][20] = {
        {12, 4, 4, 19, 12, 4, 0, 19, 19, 7, 4, 20, 18, 20, 0, 11, 15, 11, 0, 2},
        {4, 19, 19, 7, 4, 20, 18, 20, 0, 11, 15, 11, 0, 2, 4, 0, 19, 19, 4, 13}
    };
    int result[2][20];

    matrixMultiplication(key, message, result);

    printf("Ciphertext: ");
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 20; j++) {
            printf("%c", result[i][j] + 'a'); 
        }
    }
    printf("\n");

    return 0;
}

