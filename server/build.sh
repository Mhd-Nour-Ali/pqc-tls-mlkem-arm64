#!/bin/bash
set -e

# ML-KEM raw benchmark
gcc mlkem_raw_warmup_server_bench.c -o mlkem_raw_server \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lcrypto -lssl -ldl -lpthread \
    -O3

# ML-KEM TLS benchmark
gcc mlkem_tls_server_bench.c -o mlkem_tls_server \
    -I/usr/local/include \
    -L/usr/local/lib \
    -loqs -lcrypto -lssl -ldl -lpthread \
    -O3

# X25519 raw benchmark
gcc x25519_raw_warmup_server.c -o x25519_raw_server \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lcrypto -lssl -ldl -lpthread \
    -O3

# X25519 TLS benchmark
gcc x25519_tls_server_bench.c -o x25519_tls_server \
    -I/usr/local/include \
    -L/usr/local/lib \
    -lcrypto -lssl -ldl -lpthread \
    -O3

