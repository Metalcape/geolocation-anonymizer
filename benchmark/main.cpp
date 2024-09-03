#include "libbfv.h"
#include "libbfvcuda.h"

#include <benchmark/benchmark.h>
#include <vector>

#define N_USERS 100
#define USER_IDX 0

// Generate data
const unsigned int number_of_elements = (unsigned int)pow(2.0, POLY_MOD_DEG - 2);
const auto data = generate_dataset(N_USERS, number_of_elements, 0.1);

class BM_SEAL_Comparison {
private:
    cpu::BFVContext bfv;
    std::vector<seal::Ciphertext> enc_data;
    seal::Ciphertext aggregate, filtered, lt;

public:
    BM_SEAL_Comparison() : bfv(cpu::get_default_parameters()) {       
        // Encrypt
        this->enc_data = cpu::encrypt_data(bfv, data);

        // Sum everything
        this->bfv.evaluator.add_many(this->enc_data, this->aggregate);

        // Filter by user
        this->bfv.evaluator.multiply(this->enc_data[USER_IDX], this->aggregate, this->filtered);
        this->bfv.evaluator.relinearize_inplace(this->filtered, this->bfv.relin_keys);
    }

    static void bfv_comparison_st(benchmark::State& state) {
        std::cout << "Running single thread benchmark with K = " << state.range(0) << std::endl;
        BM_SEAL_Comparison bm_seal;
        for (auto _ : state)
            lt_range(bm_seal.bfv, bm_seal.filtered, state.range(0), bm_seal.lt);
    }

    static void bfv_comparison_mt(benchmark::State& state) {
        std::cout << "Running multi thread benchmark with K = " << state.range(0) << std::endl;
        BM_SEAL_Comparison bm_seal;
        for (auto _ : state)
            lt_range_mt(bm_seal.bfv, bm_seal.filtered, state.range(0), bm_seal.lt);
    }

    static void bfv_comparison_poly(benchmark::State& state) {
        std::cout << "Running multi thread univariate polynomial benchmark" << std::endl;
        BM_SEAL_Comparison bm_seal;

        // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
        seal::Plaintext k("42");
        seal::Ciphertext y;
        bm_seal.bfv.encryptor.encrypt(k, y);

        // Precompute coefficients
        auto *coefficients = new std::array<int64_t, N_POLY_TERMS>();
        cpu::calc_univ_poly_coefficients(*coefficients);

        for (auto _ : state)
            lt_univariate(bm_seal.bfv, *coefficients, bm_seal.filtered, y, bm_seal.lt);

        delete coefficients;
    }
};

class BM_Troy_Comparison {
private:
    gpu::BFVContext bfv;
    std::vector<troy::Ciphertext> enc_data;
    troy::Ciphertext aggregate, filtered, lt;

public:
    BM_Troy_Comparison() : bfv(gpu::get_default_parameters()) {       
        // Encrypt
        this->enc_data = encrypt_data(bfv, data);

        // Sum everything
        // this->bfv.evaluator.add_many(this->enc_data, this->aggregate);

        // aggregate.to_device_inplace();
        bfv.encryptor.encrypt_zero_asymmetric(aggregate);
        std::for_each(this->enc_data.begin(), this->enc_data.end(), [&](troy::Ciphertext &ctx) {
            bfv.evaluator.add_inplace(this->aggregate, ctx.to_device());
        });
        // aggregate.to_host_inplace();

        // Filter by user
        troy::Ciphertext user_data = this->enc_data[USER_IDX].to_device();
        troy::Ciphertext result = this->bfv.evaluator.multiply_new(user_data, aggregate);
        filtered = bfv.evaluator.relinearize_new(result, bfv.relin_keys);
        // filtered.to_host_inplace();
    }

    static void bfv_comparison_gpu(benchmark::State& state) {
        std::cout << "Running GPU benchmark with K = " << state.range(0) << std::endl;
        BM_Troy_Comparison bm_troy;
        for (auto _ : state)
            gpu::lt_range_mt(bm_troy.bfv, bm_troy.filtered, state.range(0), bm_troy.lt);
    }

    static void bfv_comparison_gpu_poly(benchmark::State& state) {
        std::cout << "Running GPU univariate polynomial benchmark with K = " << state.range(0) << std::endl;
        BM_Troy_Comparison bm_troy;

        // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
        troy::Plaintext k;
        bm_troy.bfv.batch_encoder.encode(std::vector<uint64_t>(bm_troy.bfv.batch_encoder.slot_count(), 42), k);
        troy::Ciphertext y;
        bm_troy.bfv.encryptor.encrypt_asymmetric(k, y);

        // Precompute coefficients
        auto *coefficients = new std::array<int64_t, N_POLY_TERMS>();
        gpu::calc_univ_poly_coefficients(*coefficients);

        for (auto _ : state)
            gpu::lt_univariate(bm_troy.bfv, *coefficients, bm_troy.filtered, y, bm_troy.lt);

    }
};

int main(int argc, char** argv) {

    std::vector<std::string> args;
    for(int i = 0; i < argc; ++i) {
        args.push_back(std::string(argv[i]));
    }

    bool has_type = false;
    for(std::string arg : args) {
        has_type = arg.find("--type") != std::string::npos;
        if(has_type) {
            if (arg == "--type=mt") {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_mt)->DenseRange(10, 20, 1);
            } else if (arg == "--type=st") {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_st)->DenseRange(10, 20, 1);
            } else if (arg == "--type=poly") {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_poly);
            } else if (arg == "--type=gpu") {
                BENCHMARK(BM_Troy_Comparison::bfv_comparison_gpu)->DenseRange(10, 20, 1);
            } else if (arg == "--type=poly_gpu") {
                BENCHMARK(BM_Troy_Comparison::bfv_comparison_gpu_poly);
            }
            break;
        }
    }
    if(!has_type) {
        BENCHMARK(BM_SEAL_Comparison::bfv_comparison_mt)->DenseRange(10, 20, 1);
    }

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
