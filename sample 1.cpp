#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void handle_client(SSL *ssl) {
    char buffer[1024];
    int bytes;

    const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!";

    SSL_read(ssl, buffer, sizeof(buffer)); // Read the incoming request

    SSL_write(ssl, response, strlen(response)); // Send the response

    SSL_shutdown(ssl); // Shutdown the SSL connection
    SSL_free(ssl); // Free the SSL structure
}

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    int server, client;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create SSL context
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "Error creating SSL context\n");
        exit(EXIT_FAILURE);
    }

    // Load certificate and key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading certificate\n");
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error loading private key\n");
        exit(EXIT_FAILURE);
    }

    // Create server socket
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        fprintf(stderr, "Error creating socket\n");
        exit(EXIT_FAILURE);
    }

    // Bind server socket
    // (Assuming localhost on port 4433)
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(4433);
    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error binding socket\n");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server, 5) < 0) {
        fprintf(stderr, "Error listening on socket\n");
        exit(EXIT_FAILURE);
    }

    printf("Server is running on port 4433\n");

    while (1) {
        // Accept incoming connection
        client = accept(server, NULL, NULL);
        if (client < 0) {
            fprintf(stderr, "Error accepting connection\n");
            exit(EXIT_FAILURE);
        }

        // Create SSL structure
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "Error performing SSL handshake\n");
            exit(EXIT_FAILURE);
        }

        // Handle client request
        handle_client(ssl);
    }

    // Close server socket
    close(server);

    // Free SSL context
    SSL_CTX_free(ctx);

    return 0;
}

