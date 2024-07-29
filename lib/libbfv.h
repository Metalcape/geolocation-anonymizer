#include "bfv.h"

HE * create_encryption_context();
std::vector<seal::Ciphertext> encrypt_data(HE &bfv, std::vector<std::vector<uint64_t>> data);
void print_plaintext(HE &he, const seal::Plaintext &ptx, size_t n);
void print_ciphertext(HE &he, const seal::Ciphertext &ctx, size_t n);
void mod_exp(HE &he, const seal::Ciphertext &x, uint64_t exponent, seal::Ciphertext &result);
// void equate(HE &he, const Ciphertext &x, const Ciphertext &y, Ciphertext &result);
void equate_plain(HE &he, const seal::Ciphertext &x, const seal::Plaintext &y, seal::Ciphertext &result);
void lt_range(HE &he, const seal::Ciphertext &x, uint64_t y, seal::Ciphertext &result);
