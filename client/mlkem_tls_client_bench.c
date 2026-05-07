#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

static long ms_wall() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static long ms_cpu() {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set1_groups_list(ctx, "mlkem768");   // or "x25519"

    const int N = 1001;

    // CSV header
    printf("wall_ms,cpu_ms,bytes_sent,bytes_received\n");

    for (int i = 0; i < N; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(4433);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        connect(sock, (struct sockaddr*)&addr, sizeof(addr));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        long cpu0 = ms_cpu();
        long t0   = ms_wall();
        int ret   = SSL_connect(ssl);
        long t1   = ms_wall();
        long cpu1 = ms_cpu();

        if (ret == 1) {
            long wall = t1 - t0;
            long cpu  = cpu1 - cpu0;

            long sent = BIO_number_written(SSL_get_wbio(ssl));
            long rec  = BIO_number_read(SSL_get_rbio(ssl));

            if (i > 0)   //  discard war‑up handshake
                printf("%ld,%ld,%ld,%ld\n", wall, cpu, sent, rec);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);

        usleep(20000);
    }

    SSL_CTX_free(ctx);
    return 0;
}

