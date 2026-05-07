#!/bin/bash
set -e

# ML-KEM raw benchmark
gcc mlkem_raw_warmup_client_bench.c -o mlkem_raw_client \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lcrypto -lssl -ldl -lpthread \
    -O3

# ML-KEM TLS benchmark
gcc mlkem_tls_client_bench.c -o mlkem_tls_client \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lcrypto -lssl -ldl -lpthread \
    -O3

# X25519 raw benchmark
gcc x25519_raw_warmup_client.c -o x25519_raw_client \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lcrypto -lssl -ldl -lpthread \
    -O3

# X25519 TLS benchmark
gcc x25519_tls_client_bench.c -o x25519_tls_client \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lcrypto -lssl -ldl -lpthread \
    -O3

