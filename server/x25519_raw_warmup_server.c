#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <openssl/evp.h>

double now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

double avg(double *a, int n) { double s=0; for(int i=0;i<n;i++) s+=a[i]; return s/n; }
double mn(double *a, int n) { double m=a[0]; for(int i=1;i<n;i++) if(a[i]<m) m=a[i]; return m; }
double mx(double *a, int n) { double m=a[0]; for(int i=1;i<n;i++) if(a[i]>m) m=a[i]; return m; }

int main() {
    const int N = 1000;

    double keygen_ms[N], derive_ms[N], total_ms[N];

    int sockfd, newsock;
    struct sockaddr_in addr, cli;
    socklen_t cli_len = sizeof(cli);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(9001);

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 1);

    printf("Server waiting...\n");
    newsock = accept(sockfd, (struct sockaddr*)&cli, &cli_len);
    printf("Client connected.\n");

    // Cold-start
    unsigned char srv_pk[32], srv_sk[32];
    unsigned char cli_pk[32], shared[32];

    double t0 = now_ms();
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *srv_key = NULL;

    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &srv_key);
    double t1 = now_ms();
    double cold_keygen = t1 - t0;

    size_t pk_len = 32;
    EVP_PKEY_get_raw_public_key(srv_key, srv_pk, &pk_len);

    write(newsock, srv_pk, 32);
    read(newsock, cli_pk, 32);

    double t2 = now_ms();
    EVP_PKEY *cli_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, cli_pk, 32);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(srv_key, NULL);
    EVP_PKEY_derive_init(dctx);
    EVP_PKEY_derive_set_peer(dctx, cli_pub);
    size_t slen = 32;
    EVP_PKEY_derive(dctx, shared, &slen);
    double t3 = now_ms();
    double cold_derive = t3 - t2;
    double cold_total = t3 - t0;

    printf("Cold-start: keygen=%.6f ms, derive=%.6f ms, total=%.6f ms\n\n",
           cold_keygen, cold_derive, cold_total);

    printf("keygen_ms,derive_ms,total_ms\n");

    // Steady-state
    for (int i = 0; i < N; i++) {
        double s0 = now_ms();
        EVP_PKEY_keygen(kctx, &srv_key);
        double s1 = now_ms();
        keygen_ms[i] = s1 - s0;

        EVP_PKEY_get_raw_public_key(srv_key, srv_pk, &pk_len);
        write(newsock, srv_pk, 32);
        read(newsock, cli_pk, 32);

        double s2 = now_ms();
        cli_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, cli_pk, 32);
        dctx = EVP_PKEY_CTX_new(srv_key, NULL);
        EVP_PKEY_derive_init(dctx);
        EVP_PKEY_derive_set_peer(dctx, cli_pub);
        EVP_PKEY_derive(dctx, shared, &slen);
        double s3 = now_ms();

        derive_ms[i] = s3 - s2;
        total_ms[i] = s3 - s0;

        printf("%.6f,%.6f,%.6f\n", keygen_ms[i], derive_ms[i], total_ms[i]);
    }

    printf("\nSummary:\n");
    printf("KeyGen avg=%.6f min=%.6f max=%.6f\n", avg(keygen_ms,N), mn(keygen_ms,N), mx(keygen_ms,N));
    printf("Derive avg=%.6f min=%.6f max=%.6f\n", avg(derive_ms,N), mn(derive_ms,N), mx(derive_ms,N));
    printf("Total  avg=%.6f min=%.6f max=%.6f\n", avg(total_ms,N), mn(total_ms,N), mx(total_ms,N));

    close(newsock);
    close(sockfd);
    return 0;
}

