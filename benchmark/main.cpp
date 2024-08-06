#include "libbfv.h"

#include <benchmark/benchmark.h>
#include <vector>

#define N_USERS 100
#define USER_IDX 0

using namespace seal;

class BM_SEAL_Comparison {
private:
    BFVContext bfv;
    std::vector<std::vector<uint64_t>> data;
    std::vector<Ciphertext> enc_data;
    Ciphertext aggregate, filtered, lt;

public:
    BM_SEAL_Comparison() : bfv(get_default_parameters()) {
        // Generate data
        unsigned int number_of_elements = (unsigned int)pow(2.0, POLY_MOD_DEG - 2);
        this->data = generate_dataset(N_USERS, number_of_elements, 0.1);
        
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
};

int main(int argc, char** argv) {

    std::vector<std::string> args;
    for(int i = 0; i < argc; ++i) {
        args.push_back(std::string(argv[i]));
    }

    for(std::string arg : args) {
        if(arg.find("--type") != std::string::npos) {
            if (arg == "--type=mt") {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_mt)->DenseRange(10, 20, 1);
            } else if (arg == "--type=st") {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_st)->DenseRange(10, 20, 1);
            } else {
                BENCHMARK(BM_SEAL_Comparison::bfv_comparison_st)->DenseRange(10, 20, 1);
            }
            
            break;
        }
    }

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
