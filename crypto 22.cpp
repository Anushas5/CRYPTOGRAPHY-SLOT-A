// S-DES Key Generation
void generateSubkeys(key) {
    // Implementation for generating subkeys
}

// S-DES Encryption
void encryptSDES(plaintextBlock, subkeys) {
    ciphertextBlock = encryptSDES(plaintextBlock XOR IV, subkeys);
    IV = ciphertextBlock;
    return ciphertextBlock;
}

// S-DES Decryption
void decryptSDES(ciphertextBlock, subkeys) {
    decryptedBlock = decryptSDES(ciphertextBlock, subkeys) XOR IV;
    IV = ciphertextBlock;
    return decryptedBlock;
}

// Main function
int main() {
    // S-DES Key Generation
    subkeys = generateSubkeys(key);

    // Initialization Vector (IV)
    IV = 0b10101010; // Binary IV: 1010 1010

    // Test data
    plaintextBlocks = ... // Array of binary plaintext blocks
    ciphertextBlocks = ... // Array of binary ciphertext blocks

    // Encryption and Decryption in CBC Mode
    for (each block in plaintextBlocks) {
        encryptedBlock = encryptSDES(block, subkeys);
        ciphertextBlocks.push_back(encryptedBlock);
    }

    IV = 0b10101010; // Reset IV

    for (each block in ciphertextBlocks) {
        decryptedBlock = decryptSDES(block, subkeys);
        decryptedPlaintextBlocks.push_back(decryptedBlock);
    }

    return 0;
}
