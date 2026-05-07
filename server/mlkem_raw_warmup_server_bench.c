#include <stdio.h> //printf perror
#include <stdlib.h>// malloc, free, exit
#include <string.h>// memset
#include <unistd.h>//read, write, close
#include <arpa/inet.h>// socket, bind, listen, accept, connect
#include <time.h> // clock_gettime(), CLOCK_MONOTONIC
#include <oqs/oqs.h> // ML-KEM API from liboqs

double now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

double compute_avg(double *arr, int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += arr[i];
    return sum / n;
}

double compute_min(double *arr, int n) {
    double m = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] < m) m = arr[i];
    return m;
}

double compute_max(double *arr, int n) {
    double m = arr[0];
    for (int i = 1; i < n; i++) if (arr[i] > m) m = arr[i];
    return m;
}

int main(void) {
    const int N = 1000; // steady-state handshakes

    double keygen_ms[N];
    double decaps_ms[N];
    double total_ms[N];

    int sockfd = -1, newsock = -1;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);

    OQS_KEM *kem = NULL;
    uint8_t *pk = NULL, *sk = NULL, *ct = NULL, *ss = NULL;

    // --- TCP SETUP ---
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); goto cleanup; }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(9000);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind"); goto cleanup;
    }

    if (listen(sockfd, 1) < 0) {
        perror("listen"); goto cleanup;
    }

    printf("Server: waiting for client...\n");
    newsock = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_len);
    if (newsock < 0) { perror("accept"); goto cleanup; }
    printf("Server: client connected.\n");

    // --- ML-KEM INIT ---
    kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) { fprintf(stderr, "OQS_KEM_new failed\n"); goto cleanup; }

    pk = malloc(kem->length_public_key);
    sk = malloc(kem->length_secret_key);
    ct = malloc(kem->length_ciphertext);
    ss = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    // --- COLD-START HANDSHAKE (1st) ---
    double t0 = now_ms();
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n");
        goto cleanup;
    }
    double t1 = now_ms();
    double cold_keygen = t1 - t0;

    if (write(newsock, pk, kem->length_public_key) != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "send pk failed\n");
        goto cleanup;
    }

    if (read(newsock, ct, kem->length_ciphertext) != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "recv ct failed\n");
        goto cleanup;
    }

    double t2 = now_ms();
    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) {
        fprintf(stderr, "decaps failed\n");
        goto cleanup;
    }
    double t3 = now_ms();
    double cold_decaps = t3 - t2;
    double cold_total  = t3 - t0;

    printf("Cold-start (server): keygen=%.6f ms, decaps=%.6f ms, total=%.6f ms\n\n",
           cold_keygen, cold_decaps, cold_total);

    // --- STEADY-STATE CSV HEADER ---
    printf("keygen_ms,decaps_ms,total_ms\n");

    // --- STEADY-STATE HANDSHAKES ---
    for (int i = 0; i < N; i++) {

        double s0 = now_ms();
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
            fprintf(stderr, "keypair failed\n");
            goto cleanup;
        }
        double s1 = now_ms();
        keygen_ms[i] = s1 - s0;

        if (write(newsock, pk, kem->length_public_key) != (ssize_t)kem->length_public_key) {
            fprintf(stderr, "send pk failed\n");
            goto cleanup;
        }

        if (read(newsock, ct, kem->length_ciphertext) != (ssize_t)kem->length_ciphertext) {
            fprintf(stderr, "recv ct failed\n");
            goto cleanup;
        }

        double s2 = now_ms();
        if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) {
            fprintf(stderr, "decaps failed\n");
            goto cleanup;
        }
        double s3 = now_ms();
        decaps_ms[i] = s3 - s2;
        total_ms[i]  = s3 - s0;

        printf("%.6f,%.6f,%.6f\n", keygen_ms[i], decaps_ms[i], total_ms[i]);
    }

    // --- SUMMARY (STEADY-STATE ONLY) ---
    printf("\nSummary steady-state (%d handshakes):\n", N);
    printf("KeyGen: avg=%.6f ms, min=%.6f, max=%.6f\n",
           compute_avg(keygen_ms, N),
           compute_min(keygen_ms, N),
           compute_max(keygen_ms, N));

    printf("Decaps: avg=%.6f ms, min=%.6f, max=%.6f\n",
           compute_avg(decaps_ms, N),
           compute_min(decaps_ms, N),
           compute_max(decaps_ms, N));

    printf("Total:  avg=%.6f ms, min=%.6f, max=%.6f\n",
           compute_avg(total_ms, N),
           compute_min(total_ms, N),
           compute_max(total_ms, N));

    // --- CLEANUP ---
cleanup:
	if(pk) free(pk);
	if(sk) free(sk);
	if(ct) free(ct);
	if(ss) free(ss);
	if(kem) OQS_KEM_free(kem);
	if(newsock >= 0) close(newsock);
	if(sockfd >= 0) close(sockfd); 
 /*   free(pk); free(sk); free(ct); free(ss);
    OQS_KEM_free(kem);
    close(newsock);
    close(sockfd);
*/
    return 0;
}

