#include "bfv.h"

using namespace seal;

// Constructors
HEContext::HEContext(const seal::EncryptionParameters &parms) : parms(parms), context(parms), keygen(context) {
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
}

HE::HE(const seal::EncryptionParameters &parms) : HEContext(parms), encryptor(context, public_key), evaluator(context), decryptor(context, secret_key), batch_encoder(context) {}

// Functions
HE * create_encryption_context() {
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = pow(2.0, POLY_MOD_DEG);

    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PLAIN_MOD);

    HE *bfv = new HE(parms);
    return bfv;
}

std::vector<Ciphertext> encrypt_data(HE &bfv, std::vector<std::vector<uint64_t>> data) {
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

void print_plaintext(HE &he, const Plaintext &ptx, size_t n) {
    std::vector<uint64_t> decoded_ptx;
    he.batch_encoder.decode(ptx, decoded_ptx);
    for(int i = 0; i < n; ++i)
        std::cout << decoded_ptx[i] << ' ';
    std::cout << std::endl;
}

void print_ciphertext(HE &he, const Ciphertext &ctx, size_t n) {
    Plaintext ptx;
    he.decryptor.decrypt(ctx, ptx);
    print_plaintext(he, ptx, n);
}

void mod_exp(HE &he, const Ciphertext &x, uint64_t exponent, Ciphertext &result) {
    Plaintext plain_one("1");
    Ciphertext base(x);
    he.encryptor.encrypt(plain_one, result);

    // Compute modular exponent by square and multiply
    // evaluator.exponentiate_inplace(result, P - 1, relin_keys);
    while (exponent > 0)
    {
        if(exponent % 2 == 1) {
            he.evaluator.multiply_inplace(result, base);
            he.evaluator.relinearize_inplace(result, he.relin_keys);
        }
        exponent >>= 1;
        he.evaluator.square_inplace(base);
        he.evaluator.relinearize_inplace(base, he.relin_keys);
        // std::cout << he.decryptor.invariant_noise_budget(base) << std::endl;
    }
}

void equate_plain(HE &he, const Ciphertext &x, const Plaintext &y, Ciphertext &result) {
    // Equate
    // EQ(x, y) = 1 - (x - y)^p-1

    Plaintext plain_one("1");
    Ciphertext base;
    he.evaluator.sub_plain(x, y, base);

    uint64_t exponent = PLAIN_MOD - 1;
    mod_exp(he, base, exponent, result);
    he.evaluator.negate_inplace(result);
    he.evaluator.relinearize_inplace(result, he.relin_keys);
    he.evaluator.add_plain_inplace(result, plain_one);
}

void lt_range(HE &he, const Ciphertext &x, uint64_t y, Ciphertext &result) {
    // Range comparison from 0 to threshold - 1

    // Equals [i][j] == 1 if x[j] == i, 0 otherwise
    std::vector<Ciphertext> equals(y);

    for(uint64_t i = 0; i < y; ++i) {
        Plaintext ptx(std::to_string(i));
        equate_plain(he, x, ptx, equals[i]);
        // print_ciphertext(he, equals[i], 14);
    }

    // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
    he.evaluator.add_many(equals, result);
}
