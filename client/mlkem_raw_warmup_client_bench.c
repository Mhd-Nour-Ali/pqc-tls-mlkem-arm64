#include <stdio.h> //printf, perror
#include <stdlib.h> // malloc, free, exit
#include <string.h>// memset
#include <unistd.h> // read, write, close
#include <arpa/inet.h>// socket, bind, listen, accept, connect
#include <time.h>// clock_gettime(), CLOCK_MONOTONIC
#include <oqs/oqs.h>// ML_KEM API from liboqs

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

    double encaps_ms[N];
    double total_ms[N];

    int sockfd = -1;
    struct sockaddr_in serv_addr;

    OQS_KEM *kem = NULL;
    uint8_t *pk = NULL, *ct = NULL, *ss = NULL;

    // --- TCP CONNECT ---
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); goto cleanup; }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(9000);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("inet_pton"); goto cleanup;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect"); goto cleanup;
    }

    // --- ML-KEM INIT ---
    kem = OQS_KEM_new("ML-KEM-768");
    if (!kem) { fprintf(stderr, "OQS_KEM_new failed\n"); goto cleanup; }

    pk = malloc(kem->length_public_key);
    ct = malloc(kem->length_ciphertext);
    ss = malloc(kem->length_shared_secret);

    if (!pk || !ct || !ss) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    // --- COLD-START HANDSHAKE (1st) ---
    if (read(sockfd, pk, kem->length_public_key) != (ssize_t)kem->length_public_key) {
        fprintf(stderr, "recv pk (cold) failed\n");
        goto cleanup;
    }

    double t0 = now_ms();
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
        fprintf(stderr, "encaps (cold) failed\n");
        goto cleanup;
    }
    double t1 = now_ms();
    double cold_encaps = t1 - t0;

    if (write(sockfd, ct, kem->length_ciphertext) != (ssize_t)kem->length_ciphertext) {
        fprintf(stderr, "send ct (cold) failed\n");
        goto cleanup;
    }

    printf("Cold-start (client): encaps=%.6f ms\n\n",
           cold_encaps);

    // --- STEADY-STATE CSV HEADER ---
    printf("encaps_ms\n");

    // --- STEADY-STATE HANDSHAKES ---
    for (int i = 0; i < N; i++) {

        if (read(sockfd, pk, kem->length_public_key) != (ssize_t)kem->length_public_key) {
            fprintf(stderr, "recv pk failed\n");
            goto cleanup;
        }

        double s0 = now_ms();
        if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
            fprintf(stderr, "encaps failed\n");
            goto cleanup;
        }
        double s1 = now_ms();
        encaps_ms[i] = s1 - s0;

        if (write(sockfd, ct, kem->length_ciphertext) != (ssize_t)kem->length_ciphertext) {
            fprintf(stderr, "send ct failed\n");
            goto cleanup;
        }

        printf("%.6f\n", encaps_ms[i]);
    }

    // --- SUMMARY (STEADY-STATE ONLY) ---
    printf("\nSummary steady-state (%d handshakes):\n", N);
    printf("Encaps: avg=%.6f ms, min=%.6f, max=%.6f\n",
           compute_avg(encaps_ms, N),
           compute_min(encaps_ms, N),
           compute_max(encaps_ms, N));

    // --- CLEANUP ---
cleanup:
	if(pk) free(pk);
	if(ct) free(ct);
	if(ss) free(ss);
	if(kem) OQS_KEM_free(kem);
	if(sockfd >= 0) close(sockfd);
/*    free(pk); free(ct); free(ss);
    OQS_KEM_free(kem);
    close(sockfd);
*/
    return 0;
}

