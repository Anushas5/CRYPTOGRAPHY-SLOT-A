#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int generate_certificate(const char *cert_file, const char *key_file) {
    X509 *x509;
    EVP_PKEY *pkey;
    X509_NAME *name;
    RSA *rsa;
    FILE *fp;

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Generate RSA key
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (rsa == NULL) {
        fprintf(stderr, "Error generating RSA key\n");
        return 1;
    }

    // Create EVP_PKEY structure
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        fprintf(stderr, "Error creating EVP_PKEY structure\n");
        RSA_free(rsa);
        return 1;
    }

    // Assign RSA key to EVP_PKEY
    if (EVP_PKEY_assign_RSA(pkey, rsa) == 0) {
        fprintf(stderr, "Error assigning RSA key to EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return 1;
    }

    // Create X509 certificate
    x509 = X509_new();
    if (x509 == NULL) {
        fprintf(stderr, "Error creating X509 certificate\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set validity
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year validity

    // Set subject name
    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"example.com", -1, -1, 0);

    // Set issuer name
    X509_set_issuer_name(x509, name);

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Sign certificate
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        fprintf(stderr, "Error signing X509 certificate\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Write certificate to file
    fp = fopen(cert_file, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening certificate file for writing\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 1;
    }
    PEM_write_X509(fp, x509);
    fclose(fp);

    // Write private key to file
    fp = fopen(key_file, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening private key file for writing\n");
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return 1;
    }
    PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);

    // Clean up
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return 0;
}

int main() {
    const char *cert_file = "server.crt";
    const char *key_file = "server.key";
    if (generate_certificate(cert_file, key_file) != 0) {
        fprintf(stderr, "Error generating certificate\n");
        return 1;
    }
    printf("Certificate generated successfully\n");
    return 0;
}

