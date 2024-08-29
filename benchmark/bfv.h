#pragma once

#include <SEAL-4.1/seal/seal.h>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <execution>
#include <tbb/parallel_for_each.h>
#include <thread>

#define N_MULT 20
#define POLY_MOD_DEG 15
#define PLAIN_MOD 65537
#define N_POLY_TERMS PLAIN_MOD/2+1

class BFVContext {
public:
    seal::EncryptionParameters parms;
    seal::SEALContext context;
    seal::KeyGenerator keygen;
    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;
    seal::Encryptor encryptor;
    seal::Evaluator evaluator;
    seal::Decryptor decryptor;
    seal::BatchEncoder batch_encoder;

    BFVContext(const seal::EncryptionParameters &parms);
};
