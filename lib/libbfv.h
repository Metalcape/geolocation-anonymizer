#include "bfv.h"

using namespace seal;

class HEContext {
public:
    EncryptionParameters parms;
    SEALContext context;
    KeyGenerator keygen;
    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;

    HEContext(const seal::EncryptionParameters &parms) : parms(parms), context(parms), keygen(context) {
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
    }
};

class HE : public HEContext {
public:
    Encryptor encryptor;
    Evaluator evaluator;
    Decryptor decryptor;
    BatchEncoder batch_encoder;

    HE(const seal::EncryptionParameters &parms) : HEContext(parms), encryptor(context, public_key), evaluator(context), decryptor(context, secret_key), batch_encoder(context) {}
};

HE * create_encryption_context();
std::vector<Ciphertext> encrypt_data(HE &bfv, std::vector<std::vector<uint64_t>> data);
void print_plaintext(HE &he, const Plaintext &ptx, size_t n);
void print_ciphertext(HE &he, const Ciphertext &ctx, size_t n);
void mod_exp(HE &he, const Ciphertext &x, uint64_t exponent, Ciphertext &result);
// void equate(HE &he, const Ciphertext &x, const Ciphertext &y, Ciphertext &result);
void equate_plain(HE &he, const Ciphertext &x, const Plaintext &y, Ciphertext &result);
void lt_range(HE &he, const Ciphertext &x, uint64_t y, Ciphertext &result);
