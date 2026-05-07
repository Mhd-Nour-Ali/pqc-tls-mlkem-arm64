# Performance Evaluation of ML-KEM (FIPS 203) in TLS 1.3 on ARM64

This repository contains the benchmarking code used to evaluate the performance of
ML-KEM-768 (FIPS 203) inside a full TLS 1.3 handshake, compared directly against X25519.
The experiments were executed on an ARM64 environment using OpenSSL and liboqs.

## Repository Structure

- client/  
  ML-KEM and X25519 client benchmarks (raw and TLS)

- server/  
  ML-KEM and X25519 server benchmarks (raw and TLS)

- scripts/  
  (Empty for now) Will contain benchmark automation and CSV parsing utilities

- results/  
  (Empty for now) Will contain example CSV outputs from benchmark runs

## Build Instructions

Each side has its own build script:

    cd client
    ./build.sh

    cd ../server
    ./build.sh

## Run Instructions

Example TLS benchmark run:

    ./mlkem_tls_server 4433
    ./mlkem_tls_client 127.0.0.1 4433

## Notes

- Requires OpenSSL 3.x and liboqs installed under /usr/local
- All binaries are compiled with -O3 for consistent benchmarking
- The full experimental report (PDF) is shared in my LinkedIn post

