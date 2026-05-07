#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

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
    signal(SIGPIPE, SIG_IGN);

    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM);
    SSL_CTX_set1_groups_list(ctx, "x25519");   // or "x25519"

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 128);

    printf("Server ready on port 4433...\n");
    printf("wall_ms,cpu_ms,bytes_sent,bytes_received\n");
    const int N = 1001;	
    int count = 0;

    while (count < N) {
        int client_fd = accept(listen_fd, NULL, NULL);
	if (client_fd < 0)
		continue;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        long cpu0 = ms_cpu();
        long t0   = ms_wall();
        int ret   = SSL_accept(ssl);
        long t1   = ms_wall();
        long cpu1 = ms_cpu();

        if (ret == 1) {
            long wall = t1 - t0;
            long cpu  = cpu1 - cpu0;

            long sent = BIO_number_written(SSL_get_wbio(ssl));
            long rec  = BIO_number_read(SSL_get_rbio(ssl));

            if (count > 0)   //  discard warm-up handshake
                printf("%ld,%ld,%ld,%ld\n", wall, cpu, sent, rec);
        }
	
	count++;

        SSL_shutdown(ssl);
        shutdown(client_fd, SHUT_RDWR);
        SSL_free(ssl);
        close(client_fd);
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    return 0;
}

