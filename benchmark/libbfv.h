#include "bfv.h"

seal::EncryptionParameters get_default_parameters();
std::vector<seal::Ciphertext> encrypt_data(BFVContext &bfv, std::vector<std::vector<uint64_t>> data);
void print_plaintext(BFVContext &bfv, const seal::Plaintext &ptx, size_t n);
void print_ciphertext(BFVContext &bfv, const seal::Ciphertext &ctx, size_t n);
void mod_exp(BFVContext &bfv, const seal::Ciphertext &x, uint64_t exponent, seal::Ciphertext &result);
// void equate(BFVContext &bfv, const Ciphertext &x, const Ciphertext &y, Ciphertext &result);
void equate_plain(BFVContext &bfv, const seal::Ciphertext &x, const seal::Plaintext &y, seal::Ciphertext &result);
void lt_range(BFVContext &bfv, const seal::Ciphertext &x, uint64_t y, seal::Ciphertext &result);
