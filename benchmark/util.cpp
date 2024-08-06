
#include "bfv.h"

std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows, unsigned int cols, double density) {
    if (density < 0.0 || density > 1.0) {
        throw std::invalid_argument("density must be between 0.0 and 1.0");
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::bernoulli_distribution d(density);

    std::vector<std::vector<uint64_t>> matrix(rows, std::vector<uint64_t>(cols));

    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            matrix[i][j] = d(gen);
        }
    }

    return matrix;
}

void print_plaintext(BFVContext &bfv, const seal::Plaintext &ptx, size_t n) {
    std::vector<uint64_t> decoded_ptx;
    bfv.batch_encoder.decode(ptx, decoded_ptx);
    for(int i = 0; i < n; ++i)
        std::cout << decoded_ptx[i] << ' ';
    std::cout << std::endl;
}

void print_ciphertext(BFVContext &bfv, const seal::Ciphertext &ctx, size_t n) {
    seal::Plaintext ptx;
    bfv.decryptor.decrypt(ctx, ptx);
    print_plaintext(bfv, ptx, n);
}
