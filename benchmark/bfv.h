#pragma once

#include <SEAL-4.1/seal/seal.h>
#include <vector>

#define N_MULT 20
#define POLY_MOD_DEG 15
#define PLAIN_MOD 65537

class HEContext {
public:
    seal::EncryptionParameters parms;
    seal::SEALContext context;
    seal::KeyGenerator keygen;
    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;

    HEContext(const seal::EncryptionParameters &parms);
};

class HE : public HEContext {
public:
    seal::Encryptor encryptor;
    seal::Evaluator evaluator;
    seal::Decryptor decryptor;
    seal::BatchEncoder batch_encoder;

    HE(const seal::EncryptionParameters &parms);
};
