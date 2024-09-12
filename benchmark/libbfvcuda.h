#include "bfvcuda.h"

// Global constants
const extern unsigned int cpu_count;

namespace gpu {
    // Encryption functions
    troy::EncryptionParameters get_default_parameters();
    std::vector<troy::Ciphertext> encrypt_data(BFVContext &bfv, std::vector<std::vector<uint64_t>> data);
    void mod_exp(BFVContext &bfv, const troy::Ciphertext &x, uint64_t exponent, troy::Ciphertext &result);
    // void equate(BFVContext &bfv, const Ciphertext &x, const Ciphertext &y, Ciphertext &result);
    void equate_plain(BFVContext &bfv, const troy::Ciphertext &x, const troy::Plaintext &y, troy::Ciphertext &result);
    void lt_range(BFVContext &bfv, const troy::Ciphertext &x, uint64_t y, troy::Ciphertext &result);
    void lt_range_mt(BFVContext &bfv, const troy::Ciphertext &x, uint64_t y, troy::Ciphertext &result);
    void calc_univ_poly_coefficients(std::array<int64_t, N_POLY_TERMS> &result);
    void lt_univariate(BFVContext &bfv, const std::array<int64_t, N_POLY_TERMS> &coefficients, const troy::Ciphertext &x, const troy::Ciphertext &y, troy::Ciphertext &result);

    // Utility functions
    void print_plaintext(BFVContext &bfv, const troy::Plaintext &ptx, size_t n);
    void print_ciphertext(BFVContext &bfv, const troy::Ciphertext &ctx, size_t n);
}

std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows, unsigned int cols, double chance);
std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows);
