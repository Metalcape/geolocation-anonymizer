#pragma once

#include "../troy-nova/src/troy.h"
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <execution>
#include <tbb/parallel_for_each.h>
#include <thread>

#include "constants.h"

namespace gpu {
    class BFVContext {
    public:
        troy::EncryptionParameters parms;
        troy::HeContextPointer context;
        troy::KeyGenerator keygen;
        troy::SecretKey secret_key;
        troy::PublicKey public_key;
        troy::RelinKeys relin_keys;
        troy::Encryptor encryptor;
        troy::Evaluator evaluator;
        troy::Decryptor decryptor;
        troy::BatchEncoder batch_encoder;

        BFVContext(const troy::EncryptionParameters &parms);
    };
}

