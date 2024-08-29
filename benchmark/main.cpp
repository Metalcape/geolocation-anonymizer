#include "libbfv.h"

#include <benchmark/benchmark.h>
#include <vector>

#define N_USERS 100
#define USER_IDX 0

using namespace seal;

// Generate data
const unsigned int number_of_elements = (unsigned int)pow(2.0, POLY_MOD_DEG - 2);
const auto data = generate_dataset(N_USERS, number_of_elements, 0.1);

class BM_SEAL_Comparison {
private:
    BFVContext bfv;
    std::vector<Ciphertext> enc_data;
    Ciphertext aggregate, filtered, lt;

public:
    BM_SEAL_Comparison() : bfv(get_default_parameters()) {       
        // Encrypt
        this->enc_data = encrypt_data(bfv, data);

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
        Plaintext k("42");
        Ciphertext y;
        bm_seal.bfv.encryptor.encrypt(k, y);

        // Precompute coefficients
        auto *coefficients = new std::array<int64_t, N_POLY_TERMS>();
        calc_univ_poly_coefficients(*coefficients);

        for (auto _ : state)
            lt_univariate(bm_seal.bfv, *coefficients, bm_seal.filtered, y, bm_seal.lt);

        delete coefficients;
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
