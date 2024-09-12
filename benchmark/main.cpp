#include "libbfv.h"
#include "libbfvcuda.h"

#include <benchmark/benchmark.h>
#include <vector>

#define N_USERS 100
#define USER_IDX 0

// Generate data
// const unsigned int number_of_elements = (unsigned int)pow(2.0, POLY_MOD_DEG_EXP - 2);
// const auto data = generate_dataset(N_USERS, number_of_elements, 0.1);
// const auto data = generate_dataset(N_USERS);

class BM_SEAL_Comparison {
public:
    cpu::BFVContext bfv;
    std::vector<seal::Ciphertext> enc_data;
    seal::Ciphertext aggregate, filtered, lt;

    BM_SEAL_Comparison() : bfv(cpu::get_default_parameters()) {       
        auto data = generate_dataset(N_USERS);

        // Encrypt
        this->enc_data = cpu::encrypt_data(bfv, data);

        // Sum everything
        this->bfv.evaluator.add_many(this->enc_data, this->aggregate);

        // Filter by user
        this->bfv.evaluator.multiply(this->enc_data[USER_IDX], this->aggregate, this->filtered);
        this->bfv.evaluator.relinearize_inplace(this->filtered, this->bfv.relin_keys);
    }
};

class BM_Troy_Comparison {
public:
    gpu::BFVContext bfv;
    std::vector<troy::Ciphertext> enc_data;
    troy::Ciphertext aggregate, filtered, lt;

    BM_Troy_Comparison() : bfv(gpu::get_default_parameters()) {
        auto data = generate_dataset(N_USERS);

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
};

class RangeFixtureCpu : public benchmark::Fixture {
public:
    BM_SEAL_Comparison *bm_seal;
};

class PolyFixtureCpu : public benchmark::Fixture {
public:
    BM_SEAL_Comparison *bm_seal;
    seal::Ciphertext *y;
    std::array<int64_t, N_POLY_TERMS> *coefficients;

    void SetUp(::benchmark::State& state) {
        // Precompute coefficients
        coefficients = new std::array<int64_t, N_POLY_TERMS>();
        cpu::calc_univ_poly_coefficients(*coefficients);
    }

    void TearDown(::benchmark::State& state) {
        delete coefficients;
    }
};

class RangeFixtureGpu : public benchmark::Fixture {
public:
    BM_Troy_Comparison *bm_troy;
};

class PolyFixtureGpu : public benchmark::Fixture {
public:
    BM_Troy_Comparison *bm_troy;
    troy::Ciphertext *y;
    std::array<int64_t, N_POLY_TERMS> *coefficients;

    void SetUp(::benchmark::State& state) {       
        // Precompute coefficients
        coefficients = new std::array<int64_t, N_POLY_TERMS>();
        gpu::calc_univ_poly_coefficients(*coefficients);
    }

    void TearDown(::benchmark::State& state) {
        delete coefficients;
    }
};

BENCHMARK_DEFINE_F(RangeFixtureCpu, cpu_single_threaded)(benchmark::State& state) {
    bm_seal = new BM_SEAL_Comparison();
    for (auto _ : state)
        cpu::lt_range(bm_seal->bfv, bm_seal->filtered, state.range(0), bm_seal->lt);
    delete bm_seal;
}

BENCHMARK_DEFINE_F(RangeFixtureCpu, cpu_multi_threaded)(benchmark::State& state) {
    bm_seal = new BM_SEAL_Comparison();
    for (auto _ : state)
        cpu::lt_range_mt(bm_seal->bfv, bm_seal->filtered, state.range(0), bm_seal->lt);
    delete bm_seal;
}

BENCHMARK_DEFINE_F(PolyFixtureCpu, cpu_poly_univariate)(benchmark::State& state) {
    bm_seal = new BM_SEAL_Comparison();
    
    // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
    seal::Plaintext k("42");
    y = new seal::Ciphertext();
    bm_seal->bfv.encryptor.encrypt(k, *y);

    for (auto _ : state)
        cpu::lt_univariate(bm_seal->bfv, *coefficients, bm_seal->filtered, *y, bm_seal->lt);
    
    delete bm_seal;
    delete y;
}

BENCHMARK_DEFINE_F(RangeFixtureGpu, gpu_single_threaded)(benchmark::State& state) {
    bm_troy = new BM_Troy_Comparison();
    for (auto _ : state)
        gpu::lt_range(bm_troy->bfv, bm_troy->filtered, state.range(0), bm_troy->lt);
    delete bm_troy;
}

BENCHMARK_DEFINE_F(PolyFixtureGpu, gpu_poly_univariate)(benchmark::State& state) {
    bm_troy = new BM_Troy_Comparison();

    // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
    troy::Plaintext k = bm_troy->bfv.batch_encoder.encode_new(std::vector<uint64_t>(bm_troy->bfv.batch_encoder.slot_count(), 42));
    y = new troy::Ciphertext(bm_troy->bfv.encryptor.encrypt_asymmetric_new(k));

    for (auto _ : state)
        gpu::lt_univariate(bm_troy->bfv, *coefficients, bm_troy->filtered, *y, bm_troy->lt);
    
    delete bm_troy;
    delete y;
}

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
                BENCHMARK_REGISTER_F(RangeFixtureCpu, cpu_multi_threaded)->DenseRange(10, 20, 1);             
            } else if (arg == "--type=st") {
                BENCHMARK_REGISTER_F(RangeFixtureCpu, cpu_single_threaded)->DenseRange(10, 20, 1);           
            } else if (arg == "--type=poly") {
                BENCHMARK_REGISTER_F(PolyFixtureCpu, cpu_poly_univariate);
            } else if (arg == "--type=gpu") {
                BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_single_threaded)->DenseRange(10, 20, 1);
            } else if (arg == "--type=gpu_range") {
                BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_single_threaded)->DenseRange(10, 80, 5);
            } else if (arg == "--type=gpu_poly") {
                BENCHMARK_REGISTER_F(PolyFixtureGpu, gpu_poly_univariate);
            }
            break;
        }
    }
    if(!has_type) {
        BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_single_threaded)->DenseRange(10, 20, 1);
    }

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
