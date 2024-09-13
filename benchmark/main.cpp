#include "libbfv.h"
#include "libbfvcuda.h"

#include <benchmark/benchmark.h>
#include <vector>

#define N_USERS 100
#define USER_IDX 0

class RangeFixtureCpu : public benchmark::Fixture {
public:
    cpu::BFVContext *bfv;
    std::vector<std::vector<uint64_t>> data;
    std::vector<seal::Ciphertext> enc_data;
    seal::Ciphertext aggregate, filtered, lt;
};

class RangeFixtureGpu : public benchmark::Fixture {
public:
    gpu::BFVContext *bfv;
    std::vector<std::vector<uint64_t>> data;
    std::vector<troy::Ciphertext> enc_data;
    troy::Ciphertext aggregate, filtered, lt;
};

class PolyFixtureCpu : public benchmark::Fixture {
public:
    cpu::BFVContext *bfv;
    std::vector<std::vector<uint64_t>> data;
    std::vector<seal::Ciphertext> enc_data;
    seal::Ciphertext aggregate, filtered, lt, *y;
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

class PolyFixtureGpu : public benchmark::Fixture {
public:
    gpu::BFVContext *bfv;
    std::vector<std::vector<uint64_t>> data;
    std::vector<troy::Ciphertext> enc_data;
    troy::Ciphertext aggregate, filtered, lt;
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
    // Generate test data
    data = generate_dataset(N_USERS);
    bfv = new cpu::BFVContext(cpu::get_default_parameters());
    
    // Encrypt
    enc_data = cpu::encrypt_data(*bfv, data);

    // Sum everything
    bfv->evaluator.add_many(enc_data, aggregate);

    // Filter by user
    bfv->evaluator.multiply(enc_data[USER_IDX], aggregate, filtered);
    bfv->evaluator.relinearize_inplace(filtered, bfv->relin_keys);

    for (auto _ : state)
        cpu::lt_range(*bfv, filtered, state.range(0), lt);
    
    delete bfv;
}

BENCHMARK_DEFINE_F(RangeFixtureCpu, cpu_multi_threaded)(benchmark::State& state) {
    data = generate_dataset(N_USERS);
    bfv = new cpu::BFVContext(cpu::get_default_parameters());
    enc_data = cpu::encrypt_data(*bfv, data);
    bfv->evaluator.add_many(enc_data, aggregate);
    bfv->evaluator.multiply(enc_data[USER_IDX], aggregate, filtered);
    bfv->evaluator.relinearize_inplace(filtered, bfv->relin_keys);

    for (auto _ : state)
        cpu::lt_range_mt(*bfv, filtered, state.range(0), lt);
    
    delete bfv;
}

BENCHMARK_DEFINE_F(PolyFixtureCpu, cpu_poly_univariate)(benchmark::State& state) {
    data = generate_dataset(N_USERS);
    bfv = new cpu::BFVContext(cpu::get_default_parameters());
    enc_data = cpu::encrypt_data(*bfv, data);
    bfv->evaluator.add_many(enc_data, aggregate);
    bfv->evaluator.multiply(enc_data[USER_IDX], aggregate, filtered);
    bfv->evaluator.relinearize_inplace(filtered, bfv->relin_keys);

    // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
    seal::Plaintext k("42");
    y = new seal::Ciphertext();
    bfv->encryptor.encrypt(k, *y);

    for (auto _ : state)
        cpu::lt_univariate(*bfv, *coefficients, filtered, *y, lt);

    delete y;
    delete bfv;
}

BENCHMARK_DEFINE_F(RangeFixtureGpu, gpu_single_threaded)(benchmark::State& state) {
    // Generate test data
    data = generate_dataset(N_USERS);
    bfv = new gpu::BFVContext(gpu::get_default_parameters());
    
    // Encrypt
    enc_data = gpu::encrypt_data(*bfv, data);

    // Sum everything
    bfv->encryptor.encrypt_zero_asymmetric(aggregate);
    std::for_each(this->enc_data.begin(), this->enc_data.end(), [&](troy::Ciphertext &ctx) {
        bfv->evaluator.add_inplace(this->aggregate, ctx.to_device());
    });

    // Filter by user
    troy::Ciphertext user_data = this->enc_data[USER_IDX].to_device();
    troy::Ciphertext result = bfv->evaluator.multiply_new(user_data, aggregate);
    filtered = bfv->evaluator.relinearize_new(result, bfv->relin_keys);

    for (auto _ : state)
        gpu::lt_range(*bfv, filtered, state.range(0), lt);
    
    delete bfv;
}

BENCHMARK_DEFINE_F(PolyFixtureGpu, gpu_poly_univariate)(benchmark::State& state) {
    data = generate_dataset(N_USERS);
    bfv = new gpu::BFVContext(gpu::get_default_parameters());
    enc_data = gpu::encrypt_data(*bfv, data);

    bfv->encryptor.encrypt_zero_asymmetric(aggregate);
    std::for_each(this->enc_data.begin(), this->enc_data.end(), [&](troy::Ciphertext &ctx) {
        bfv->evaluator.add_inplace(this->aggregate, ctx.to_device());
    });

    troy::Ciphertext user_data = this->enc_data[USER_IDX].to_device();
    troy::Ciphertext result = bfv->evaluator.multiply_new(user_data, aggregate);
    filtered = bfv->evaluator.relinearize_new(result, bfv->relin_keys);

    // Prepare encrypted K (this algorithm does NOT require K to be in the clear)
    troy::Plaintext k = bfv->batch_encoder.encode_new(std::vector<uint64_t>(bfv->batch_encoder.slot_count(), 42));
    y = new troy::Ciphertext(bfv->encryptor.encrypt_asymmetric_new(k));

    for (auto _ : state)
        gpu::lt_univariate(*bfv, *coefficients, filtered, *y, lt);
    
    delete y;
    delete bfv;
}

BENCHMARK_DEFINE_F(RangeFixtureCpu, cpu_encryption)(benchmark::State& state) {
    data = generate_dataset(1);
    bfv = new cpu::BFVContext(cpu::get_default_parameters());
    seal::Plaintext ptx;
    seal::Ciphertext ctx;

    for (auto _ : state) {
        bfv->batch_encoder.encode(data[0], ptx);
        bfv->encryptor.encrypt(ptx, ctx);
    }
}

BENCHMARK_DEFINE_F(RangeFixtureCpu, cpu_decryption)(benchmark::State& state) {
    data = generate_dataset(1);
    bfv = new cpu::BFVContext(cpu::get_default_parameters());
    enc_data = cpu::encrypt_data(*bfv, data);
    seal::Plaintext ptx;
    seal::Ciphertext ctx;
    std::vector<uint64_t> out;

    for (auto _ : state) {
        bfv->decryptor.decrypt(enc_data[0], ptx);
        bfv->batch_encoder.decode(ptx, out);
    }
}

BENCHMARK_DEFINE_F(RangeFixtureGpu, gpu_encryption)(benchmark::State& state) {
    data = generate_dataset(1);
    bfv = new gpu::BFVContext(gpu::get_default_parameters());
    troy::Plaintext ptx;
    troy::Ciphertext ctx;

    for (auto _ : state) {
        ptx = bfv->batch_encoder.encode_new(data[0]);
        ctx = bfv->encryptor.encrypt_asymmetric_new(ptx.to_device());
    }
}

BENCHMARK_DEFINE_F(RangeFixtureGpu, gpu_decryption)(benchmark::State& state) {
    data = generate_dataset(1);  
    bfv = new gpu::BFVContext(gpu::get_default_parameters());
    enc_data = gpu::encrypt_data(*bfv, data);
    troy::Plaintext ptx;
    troy::Ciphertext ctx;
    std::vector<uint64_t> out;

    for (auto _ : state) {
        ptx = bfv->decryptor.decrypt_new(enc_data[0].to_device());
        out = bfv->batch_encoder.decode_new(ptx);
    }
}

void test_equivalence() {
    std::cout << "Setting up..." << std::endl;
    gpu::BFVContext bfv(gpu::get_default_parameters());
    std::vector<std::vector<uint64_t>> data;
    std::vector<troy::Ciphertext> enc_data;
    troy::Ciphertext aggregate, filtered, lt;

    // Use a small dataset for simplicity
    const size_t limit = 20;
    data = generate_dataset(N_USERS, limit, 0.1);
    enc_data = gpu::encrypt_data(bfv, data);
    bfv.encryptor.encrypt_zero_asymmetric(aggregate);
    std::for_each(enc_data.begin(), enc_data.end(), [&](troy::Ciphertext &ctx) {
        bfv.evaluator.add_inplace(aggregate, ctx.to_device());
    });
    troy::Ciphertext user_data = enc_data[USER_IDX].to_device();
    troy::Ciphertext result = bfv.evaluator.multiply_new(user_data, aggregate);
    filtered = bfv.evaluator.relinearize_new(result, bfv.relin_keys);
    
    std::cout << "User vector:" << std::endl;
    gpu::print_ciphertext(bfv, enc_data[USER_IDX], limit);
    std::cout << "Aggregated vector:" << std::endl;
    gpu::print_ciphertext(bfv, aggregate, limit);
    std::cout << "Filtered vector:" << std::endl;
    gpu::print_ciphertext(bfv, filtered, limit);

    troy::Ciphertext result_range, result_poly;
    std::array<int64_t, N_POLY_TERMS> *coefficients;
    const auto k_value = 10;

    coefficients = new std::array<int64_t, N_POLY_TERMS>();
    gpu::calc_univ_poly_coefficients(*coefficients);

    troy::Plaintext k = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), k_value));
    troy::Ciphertext y = bfv.encryptor.encrypt_asymmetric_new(k);

    std::cout << "Calculating k-anonimity with range method..." << std::endl;
    gpu::lt_range(bfv, filtered, k_value, result_range);
    std::cout << "Calculating k-anonimity with polynomial method..." << std::endl;
    gpu::lt_univariate(bfv, *coefficients, filtered, y, result_poly);

    std::cout << "Decrypting and decoding..." << std::endl;
    troy::Plaintext ptx_range, ptx_poly;
    bfv.decryptor.decrypt(result_range, ptx_range);
    bfv.decryptor.decrypt(result_poly, ptx_poly);

    std::vector<uint64_t> v_range, v_poly;
    bfv.batch_encoder.decode(ptx_range, v_range);
    bfv.batch_encoder.decode(ptx_poly, v_poly);

    // Convert the polynomial format into boolean format:
    // The polynomial value is negative if X - Y is negative (which implies X < Y).
    // The result is unsigned, but can be interpreted as signed by shifing it down by p/2.
    auto v_poly_original = v_poly;
    std::for_each(std::execution::par, v_poly.begin(), v_poly.end(), [&](uint64_t &i) {
        if (interpret_as_signed_mod_p(i, PLAIN_MOD) < 0)
            i = 1;  // Below the threshold k
        else
            i = 0;  // Over the threshold k
    });

    if (v_poly.size() != v_range.size())
        std::cout << "The sizes of the two vectors are not equal." << std::endl;

    if (v_poly == v_range) {
        std::cout << "OK!" << std::endl;
    } else {
        std::cout << "The two outputs are different." << std::endl;
    }

    std::cout << "Range method result: " << std::endl;
    print_vector(v_range, limit);
    std::cout << "Polynomial method result: " << std::endl;
    print_vector(v_poly_original, limit);
    print_vector(v_poly, limit);

    delete coefficients;
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
                BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_single_threaded)->DenseRange(10, 100, 5);
            } else if (arg == "--type=gpu_poly") {
                BENCHMARK_REGISTER_F(PolyFixtureGpu, gpu_poly_univariate);
            } else if (arg == "--type=cpu_enc") {
                BENCHMARK_REGISTER_F(RangeFixtureCpu, cpu_encryption);
            } else if (arg == "--type=cpu_dec") {
                BENCHMARK_REGISTER_F(RangeFixtureCpu, cpu_decryption);
            } else if (arg == "--type=gpu_enc") {
                BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_encryption);
            } else if (arg == "--type=gpu_dec") {
                BENCHMARK_REGISTER_F(RangeFixtureGpu, gpu_decryption);
            } else if (arg == "--type=test_eq") {
                test_equivalence();
            }
            break;
        }
    }
    if(!has_type) {
        test_equivalence();
        return 0;
    }

    benchmark::Initialize(&argc, argv);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
