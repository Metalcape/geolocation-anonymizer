#include "bfv.h"

namespace cpu {
    // Encryption functions
    seal::EncryptionParameters get_default_parameters();
    std::vector<seal::Ciphertext> encrypt_data(BFVContext &bfv, std::vector<std::vector<uint64_t>> data);
    void mod_exp(BFVContext &bfv, const seal::Ciphertext &x, uint64_t exponent, seal::Ciphertext &result);
    void equate_plain(BFVContext &bfv, const seal::Ciphertext &x, const seal::Plaintext &y, seal::Ciphertext &result);
    void lt_range(BFVContext &bfv, const seal::Ciphertext &x, uint64_t y, seal::Ciphertext &result);
    void lt_range_mt(BFVContext &bfv, const seal::Ciphertext &x, uint64_t y, seal::Ciphertext &result);
    void calc_univ_poly_coefficients(std::array<int64_t, N_POLY_TERMS> &result);
    void lt_univariate(BFVContext &bfv, const std::array<int64_t, N_POLY_TERMS> &coefficients, const seal::Ciphertext &x, const seal::Ciphertext &y, seal::Ciphertext &result);
}

// Utility functions
std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows, unsigned int cols, double chance);
std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows);
void print_vector(std::vector<uint64_t> v);
void print_vector(std::vector<uint64_t> v, size_t limit);
int64_t interpret_as_signed_mod_p(uint64_t x, uint64_t p);

namespace cpu {
    void print_plaintext(BFVContext &bfv, const seal::Plaintext &ptx);
    void print_ciphertext(BFVContext &bfv, const seal::Ciphertext &ctx);
    void print_plaintext(BFVContext &bfv, const seal::Plaintext &ptx, size_t limit);
    void print_ciphertext(BFVContext &bfv, const seal::Ciphertext &ctx, size_t limit);
}

