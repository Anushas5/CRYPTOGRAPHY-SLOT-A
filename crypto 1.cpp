#include <stdio.h>
#include <string.h>
void encrypt(char text[], int key) {
    int i;
    char encrypted_text[strlen(text)];

    for (i = 0; i < strlen(text); i++) {
        if (text[i] >= 'a' && text[i] <= 'z')
            encrypted_text[i] = 'a' + (text[i] - 'a' + key) % 26;
        else if (text[i] >= 'A' && text[i] <= 'Z')
            encrypted_text[i] = 'A' + (text[i] - 'A' + key) % 26;
        else
            encrypted_text[i] = text[i];
    }
    encrypted_text[i] = '\0';
    
    printf("Encrypted text: %s\n", encrypted_text);
}
int main() {
    char text[100];
    int key, i; 

    printf("Enter the text to be encrypted: ");
    fgets(text, sizeof(text), stdin);

    printf("Enter the key value (1-25): ");
    scanf("%d", &key);

    key = key % 26;

    encrypt(text, key);

    return 0;
}

