#include "bfv.h"
#include "bfvcuda.h"

const unsigned int cpu_count = std::thread::hardware_concurrency();

std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows, unsigned int cols, double chance) {
    if (chance < 0.0 || chance > 1.0) {
        throw std::invalid_argument("chance must be between 0.0 and 1.0");
    }

    std::random_device rd;
    std::vector<std::vector<uint64_t>> matrix(rows, std::vector<uint64_t>(cols, 0));

    // for (int i = 0; i < rows; ++i) {
    //     for (int j = 0; j < cols; ++j) {
    //         matrix[i][j] = d(gen);
    //     }
    // }

    std::for_each(std::execution::par, matrix.begin(), matrix.end(), [&](std::vector<uint64_t> &row) {
        std::mt19937 gen(rd());
        std::bernoulli_distribution d(chance);

        for (int j = 0; j < cols; ++j) {
            row[j] = d(gen);
        }
    });

    return matrix;
}

std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows) {
    const auto avg_region_count = {14, 26, 189, 143, 1062, 727, 919, 35};
    uint64_t slot_count = std::accumulate(avg_region_count.begin(), avg_region_count.end(), 0);

    std::random_device rd;
    std::vector<std::vector<uint64_t>> matrix(rows, std::vector<uint64_t>(slot_count, 0));

    std::for_each(std::execution::par, matrix.begin(), matrix.end(), [&](std::vector<uint64_t> &row) {
        std::mt19937 gen(rd());
        auto begin = 0;
        for (const auto& count : avg_region_count) {
            std::uniform_int_distribution<> dis(begin, begin + count - 1);
            row[dis(gen)] = 1;
            begin = count;
        }
    });

    // Print test data
    // std::cout <<  "Test data sample: " << std::endl;
    // std::cout <<  "[ ";
    // for (int i = 0; i < matrix[0].size() - 1; ++i) {
    //     std::cout <<  matrix[0][i] << ", ";
    // }
    // std::cout << matrix[0].back() << "] " << std::endl;

    return matrix;
}

void print_plaintext(cpu::BFVContext &bfv, const seal::Plaintext &ptx, size_t n) {
    std::vector<uint64_t> decoded_ptx;
    bfv.batch_encoder.decode(ptx, decoded_ptx);
    for(int i = 0; i < n; ++i)
        std::cout << decoded_ptx[i] << ' ';
    std::cout << std::endl;
}

void print_ciphertext(cpu::BFVContext &bfv, const seal::Ciphertext &ctx, size_t n) {
    seal::Plaintext ptx;
    bfv.decryptor.decrypt(ctx, ptx);
    print_plaintext(bfv, ptx, n);
}

void print_plaintext(gpu::BFVContext &bfv, const troy::Plaintext &ptx, size_t n) {
    std::vector<uint64_t> decoded_ptx;
    bfv.batch_encoder.decode(ptx, decoded_ptx);
    for(int i = 0; i < n; ++i)
        std::cout << decoded_ptx[i] << ' ';
    std::cout << std::endl;
}

void print_ciphertext(gpu::BFVContext &bfv, const troy::Ciphertext &ctx, size_t n) {
    troy::Plaintext ptx;
    bfv.decryptor.decrypt(ctx, ptx);
    print_plaintext(bfv, ptx, n);
}
