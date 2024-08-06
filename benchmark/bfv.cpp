#include "bfv.h"

namespace seal {
    bool operator==(const Ciphertext& ctx1, const Ciphertext& ctx2) {
        return ctx1.parms_id() == ctx2.parms_id() && ctx1.data() == ctx2.data();
    }
}

using namespace seal;

const unsigned int cpu_count = std::thread::hardware_concurrency();

// Constructors
BFVContext::BFVContext(const seal::EncryptionParameters &parms) : 
    parms(parms), context(parms), 
    keygen(context), 
    secret_key(keygen.secret_key()), 
    encryptor(context, secret_key), 
    evaluator(context), 
    decryptor(context, secret_key), 
    batch_encoder(context) 
{
    keygen.create_public_key(this->public_key);
    keygen.create_relin_keys(this->relin_keys);
    this->encryptor.set_public_key(this->public_key);
}

// Functions
EncryptionParameters get_default_parameters() {
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = pow(2.0, POLY_MOD_DEG);

    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MOD);
    return parms;
}

std::vector<Ciphertext> encrypt_data(BFVContext &bfv, std::vector<std::vector<uint64_t>> data) {
    std::vector<Ciphertext> enc_data(data.size());
    for(int i = 0; i < enc_data.size(); ++i) {
        Plaintext pt;
        Ciphertext ct;
        bfv.batch_encoder.encode(data[i], pt);
        bfv.encryptor.encrypt(pt, ct);
        enc_data[i] = ct;
    }
    return enc_data;
}

void mod_exp(BFVContext &bfv, const Ciphertext &x, uint64_t exponent, Ciphertext &result) {
    Plaintext plain_one("1");
    Ciphertext base(x);
    bfv.encryptor.encrypt(plain_one, result);

    // Compute modular exponent by square and multiply
    // evaluator.exponentiate_inplace(result, P - 1, relin_keys);
    while (exponent > 0)
    {
        if(exponent % 2 == 1) {
            bfv.evaluator.multiply_inplace(result, base);
            bfv.evaluator.relinearize_inplace(result, bfv.relin_keys);
        }
        exponent >>= 1;
        bfv.evaluator.square_inplace(base);
        bfv.evaluator.relinearize_inplace(base, bfv.relin_keys);
        // std::cout << bfv.decryptor.invariant_noise_budget(base) << std::endl;
    }
}

void equate_plain(BFVContext &bfv, const Ciphertext &x, const Plaintext &y, Ciphertext &result) {
    // Equate
    // EQ(x, y) = 1 - (x - y)^p-1

    Plaintext plain_one("1");
    Ciphertext base;
    bfv.evaluator.sub_plain(x, y, base);

    uint64_t exponent = PLAIN_MOD - 1;
    mod_exp(bfv, base, exponent, result);
    bfv.evaluator.negate_inplace(result);
    bfv.evaluator.relinearize_inplace(result, bfv.relin_keys);
    bfv.evaluator.add_plain_inplace(result, plain_one);
}

void lt_range(BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
    // Range comparison from 0 to threshold - 1

    // Equals [i][j] == 1 if x[j] == i, 0 otherwise
    std::vector<Ciphertext> equals(y);

    for(uint64_t i = 0; i < y; ++i) {
        Plaintext ptx(std::to_string(i));
        equate_plain(bfv, x, ptx, equals[i]);
        // print_ciphertext(he, equals[i], 14);
    }

    // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
    bfv.evaluator.add_many(equals, result);
}

void lt_range_mt(BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
    // Vector to store results
    std::vector<Ciphertext> equals(y);

    // Loop with concurrent execution
    std::for_each(std::execution::par, equals.begin(), equals.end(), [&](Ciphertext &row) {
        // auto i = std::find(equals.begin(), equals.end(), row) - equals.begin();
        auto i = &row - &equals[0];
        Plaintext ptx(std::to_string(i));
        equate_plain(bfv, x, ptx, row);
    });

    // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
    bfv.evaluator.add_many(equals, result);
}
