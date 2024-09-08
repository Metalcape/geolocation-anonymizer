#pragma once

#include <SEAL-4.1/seal/seal.h>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <execution>
#include <tbb/parallel_for_each.h>
#include <thread>

#include "constants.h"

namespace cpu {
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
}
