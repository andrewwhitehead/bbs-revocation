Registry design details: https://hackmd.io/BnXrxY5JSyaeDyQPoKzwgw

This repository contains a preliminary implementation of the non-revocation registry builder and reader, as well as a test application for benchmarking and verifying the registry generation. Rust 1.51+ is required.

The test application currently generates and a randomly-populated registry according to the given parameters. This is NOT a realistic scenario, but helps to demonstrate the worst case for registry file sizes and computation. A registry with sparse or closely grouped revocations would be smaller and easier to generate.

Run the test application with `cargo run --release --`. The following options are required:

- `-b` The registry block size. This must be currently be a multiple of 8 between 8 and 64.
- `-c` The number of registry entries.
- `-p` The percentage of revocation. Note that in real-world use cases, the distribution of entries is likely not random, and is expected to be a very low rate.

Optional parameters:

- `-o` Adjust the output filename.
- `-v` Perform verification on the registry by checking that selected indices are present or missing as expected, and verifying signatures.

# Sample Times

Executed on a 2016 Macbook Pro, single threaded computation.

## Block size 8

| Index count | Revoked % | Entries | File size (Kb) | Generation time (s) |
| ----------- | --------- | ------- | -------------- | ------------------- |
| 1,000       | 1         | 26      | 1.7            | 0.04                |
| 1,000       | 5         | 57      | 3.4            | 0.09                |
| 1,000       | 25        | 119     | 6.8            | 0.17                |
| 50,000      | 1         | 1262    | 70.5           | 1.97                |
| 50,000      | 5         | 2860    | 159            | 3.76                |
| 50,000      | 25        | 6061    | 338            | 7.75                |

## Block size 16

| Index count | Revoked % | Entries | File size (Kb) | Generation time (s) |
| ----------- | --------- | ------- | -------------- | ------------------- |
| 1,000       | 1         | 14      | 1.0            | 0.03                |
| 1,000       | 5         | 40      | 2.5            | 0.07                |
| 1,000       | 25        | 63      | 3.8            | 0.11                |
| 10,000      | 1         | 134     | 7.8            | 0.24                |
| 10,000      | 5         | 400     | 22.9           | 0.74                |
| 10,000      | 25        | 625     | 35.6           | 1.25                |
| 50,000      | 1         | 652     | 37.1           | 1.01                |
| 50,000      | 5         | 1950    | 111            | 3.42                |
| 50,000      | 25        | 3123    | 177            | 5.28                |
| 100,000     | 1         | 1320    | 75.0           | 2.26                |
| 100,000     | 5         | 3929    | 222            | 5.94                |
| 100,000     | 25        | 6249    | 354            | 10.17               |

## Block size 64

| Index count | Revoked % | Entries | File size (Kb) | Generation time (s) |
| ----------- | --------- | ------- | -------------- | ------------------- |
| 1,000       | 1         | 10      | 0.8            | 0.04                |
| 1,000       | 5         | 16      | 1.2            | 0.06                |
| 1,000       | 25        | 16      | 1.2            | 0.06                |
| 10,000      | 1         | 81      | 5.3            | 0.24                |
| 10,000      | 5         | 155     | 9.9            | 0.44                |
| 10,000      | 25        | 157     | 10.0           | 0.47                |
| 50,000      | 1         | 384     | 24.2           | 1.03                |
| 50,000      | 5         | 761     | 47.8           | 2.13                |
| 50,000      | 25        | 782     | 49.1           | 2.20                |
| 100,000     | 1         | 771     | 48.4           | 2.12                |
| 100,000     | 5         | 1535    | 96.2           | 4.01                |
| 100,000     | 25        | 1563    | 97.9           | 4.21                |
| 500,000     | 1         | 3841    | 240            | 10.58               |
| 500,000     | 5         | 7648    | 478            | 20.78               |
| 500,000     | 25        | 7813    | 489            | 21.15               |
