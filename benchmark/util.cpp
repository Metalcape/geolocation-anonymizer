#include "bfv.h"
#include "bfvcuda.h"

std::vector<std::vector<uint64_t>> generate_dataset(unsigned int rows, unsigned int cols, double chance) {
    if (chance < 0.0 || chance > 1.0) {
        throw std::invalid_argument("chance must be between 0.0 and 1.0");
    }

    std::random_device rd;
    std::vector<std::vector<uint64_t>> matrix(rows, std::vector<uint64_t>(cols, 0));

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

    return matrix;
}

void print_vector(std::vector<uint64_t> v) {
    std::cout <<  "[ ";
    for (int i = 0; i < v.size() - 1; ++i) {
        std::cout <<  v[i] << ", ";
    }
    std::cout << v.back() << "] " << std::endl;
}

void print_vector(std::vector<uint64_t> v, size_t limit) {
    std::cout <<  "[ ";
    for (int i = 0; i < v.size() - 1 && i < limit; ++i) {
        std::cout <<  v[i] << ", ";
    }
    std::cout << v.back() << "] " << std::endl;
}

namespace cpu {
    void print_plaintext(cpu::BFVContext &bfv, const seal::Plaintext &ptx) {
        std::vector<uint64_t> decoded_ptx;
        bfv.batch_encoder.decode(ptx, decoded_ptx);
        print_vector(decoded_ptx);
    }

    void print_ciphertext(cpu::BFVContext &bfv, const seal::Ciphertext &ctx) {
        seal::Plaintext ptx;
        bfv.decryptor.decrypt(ctx, ptx);
        print_plaintext(bfv, ptx);
    }

    void print_plaintext(cpu::BFVContext &bfv, const seal::Plaintext &ptx, size_t limit) {
        std::vector<uint64_t> decoded_ptx;
        bfv.batch_encoder.decode(ptx, decoded_ptx);
        print_vector(decoded_ptx, limit);
    }

    void print_ciphertext(cpu::BFVContext &bfv, const seal::Ciphertext &ctx, size_t limit) {
        seal::Plaintext ptx;
        bfv.decryptor.decrypt(ctx, ptx);
        print_plaintext(bfv, ptx, limit);
    }
}

namespace gpu {
    void print_plaintext(gpu::BFVContext &bfv, const troy::Plaintext &ptx) {
        std::vector<uint64_t> decoded_ptx;
        bfv.batch_encoder.decode(ptx, decoded_ptx);
        print_vector(decoded_ptx);
    }

    void print_ciphertext(gpu::BFVContext &bfv, const troy::Ciphertext &ctx) {
        troy::Plaintext ptx;
        troy::Ciphertext ctx_d = ctx;
        if(!ctx_d.on_device())
            ctx_d.to_device_inplace();
        bfv.decryptor.decrypt(ctx_d, ptx);
        print_plaintext(bfv, ptx);
    }

    void print_plaintext(gpu::BFVContext &bfv, const troy::Plaintext &ptx, size_t limit) {
        std::vector<uint64_t> decoded_ptx;
        bfv.batch_encoder.decode(ptx, decoded_ptx);
        print_vector(decoded_ptx, limit);
    }

    void print_ciphertext(gpu::BFVContext &bfv, const troy::Ciphertext &ctx, size_t limit) {
        troy::Plaintext ptx;
        troy::Ciphertext ctx_d = ctx;
        if(!ctx_d.on_device())
            ctx_d.to_device_inplace();
        bfv.decryptor.decrypt(ctx_d, ptx);
        print_plaintext(bfv, ptx, limit);
    }
}

int64_t interpret_as_signed_mod_p(uint64_t x, uint64_t p) {   
    if (x < (p - 1)/2)
        // x is positive
        return static_cast<int64_t>(x);
    else
        // Shift x into the negative range
        return static_cast<int64_t>(x) - static_cast<int64_t>(p - 1);
}
    
