#include "bfvcuda.h"

namespace gpu {
    using namespace troy;

    // Constructors
    gpu::BFVContext::BFVContext(const troy::EncryptionParameters &parms) : 
        parms(parms),
        context(HeContext::create(parms, 0, SecurityLevel::Classical128)), 
        keygen(context), 
        secret_key(keygen.secret_key()), 
        encryptor(context), 
        evaluator(context), 
        decryptor(context, secret_key), 
        batch_encoder(context) 
    {
        if(utils::device_count() > 0) {
            context->to_device_inplace();
            batch_encoder.to_device_inplace();
            encryptor.to_device_inplace();
            decryptor.to_device_inplace();
            keygen.to_device_inplace();
            secret_key.to_device_inplace();
        }

        evaluator = Evaluator(context);
        public_key = keygen.create_public_key(false);
        relin_keys = keygen.create_relin_keys(false);
        encryptor.set_public_key(public_key);
    }

    // Functions
    EncryptionParameters get_default_parameters() {
        EncryptionParameters parms(SchemeType::BFV);
        size_t poly_modulus_degree = pow(2.0, POLY_MOD_DEG_EXP);

        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::bfv_default(poly_modulus_degree, SecurityLevel::Classical128));
        parms.set_plain_modulus(PLAIN_MOD);
        return parms;
    }

    std::vector<Ciphertext> encrypt_data(gpu::BFVContext &bfv, std::vector<std::vector<uint64_t>> data) {
        std::vector<Ciphertext> enc_data(data.size());
        for(int i = 0; i < enc_data.size(); ++i) {
            Plaintext pt = bfv.batch_encoder.encode_new(data[i]);
            Ciphertext ct = bfv.encryptor.encrypt_asymmetric_new(pt.to_device());
            enc_data[i] = ct.to_host();
        }
        return enc_data;
    }

    void mod_exp(gpu::BFVContext &bfv, const Ciphertext &x, uint64_t exponent, Ciphertext &result) {
        Plaintext plain_one = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), 1)).to_device();
        Ciphertext base(x);
        result = bfv.encryptor.encrypt_asymmetric_new(plain_one);

        // Compute modular exponent by square and multiply
        // evaluator.exponentiate_inplace(result, P - 1, relin_keys);
        if(!result.on_device())
            result.to_device_inplace();
        if(!base.on_device())
            base.to_device_inplace();
        
        if (exponent == 1) {
            result = x;
            return;
        }

        uint64_t initial_exponent = exponent;
        while (exponent > 0)
        {
            if(exponent % 2 == 1) {
                bfv.evaluator.multiply_inplace(result, base);
                result = bfv.evaluator.relinearize_new(result, bfv.relin_keys);
            }
            exponent >>= 1;
            bfv.evaluator.square_inplace(base);
            base = bfv.evaluator.relinearize_new(base, bfv.relin_keys);
            // std::cout << bfv.decryptor.invariant_noise_budget(base) << std::endl;
        }

        if(bfv.decryptor.invariant_noise_budget(result) <= 0) {
            // std::cout << "mod_exp: out of noise budget while calculating exp(X, " << exponent << ")!" << std::endl;
            std::string err_msg("mod_exp: out of noise budget while calculating exp(X, " + std::to_string(initial_exponent) + ")!");
            throw std::logic_error(err_msg);
        }
    }

    void equate_plain(gpu::BFVContext &bfv, const Ciphertext &x, const Plaintext &y, Ciphertext &result) {
        // Equate
        // EQ(x, y) = 1 - (x - y)^p-1

        Plaintext plain_one = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), 1));
        Plaintext Y = y;
        Ciphertext X = x;

        if(!X.on_device())
            X.to_device_inplace();
        if(!Y.on_device())
            Y.to_device_inplace();

        Ciphertext base = bfv.evaluator.sub_plain_new(X, Y);

        uint64_t exponent = PLAIN_MOD - 1;
        mod_exp(bfv, base, exponent, result);
        bfv.evaluator.negate_inplace(result);
        bfv.evaluator.relinearize_inplace(result, bfv.relin_keys);
        bfv.evaluator.add_plain_inplace(result, plain_one);
    }

    void lt_range(gpu::BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
        // Range comparison from 0 to threshold - 1

        // Equals [i][j] == 1 if x[j] == i, 0 otherwise
        std::vector<Ciphertext> equals(y);

        for(uint64_t i = 0; i < y; ++i) {
            Plaintext ptx = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), i));
            equate_plain(bfv, x, ptx, equals[i]);
            // print_ciphertext(he, equals[i], 14);
        }

        // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
        bfv.encryptor.encrypt_zero_asymmetric(result);
        std::for_each(equals.begin(), equals.end(), [&](Ciphertext &ctx) {
            ctx.to_device_inplace();
            bfv.evaluator.add_inplace(result, ctx);
        });
    }

    void lt_range_mt(gpu::BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
        // Vector to store results
        std::vector<Ciphertext> equals(y);

        // Loop with concurrent execution
        std::for_each(std::execution::par, equals.begin(), equals.end(), [&](Ciphertext &row) {
            // auto i = std::find(equals.begin(), equals.end(), row) - equals.begin();
            auto i = &row - &equals[0];
            Plaintext ptx = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), i));
            equate_plain(bfv, x, ptx, row);
        });

        // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
        bfv.encryptor.encrypt_zero_asymmetric(result);
        std::for_each(equals.begin(), equals.end(), [&](Ciphertext &ctx) {
            ctx.to_device_inplace();
            bfv.evaluator.add_inplace(result, ctx);
        });
    }

    constexpr int64_t mod_exp(int64_t base, int64_t exponent, int64_t p) {
        int64_t result = 1;
        while (exponent > 0)
        {
            if(exponent % 2 == 1) {
                result = (result * base) % p;
            }
            exponent >>= 1;
            base = (base * base) % p;
        }

        return result;
    }

    int64_t mod_sum(const int64_t& a, const int64_t& b) {
        return (a + b) % PLAIN_MOD;
    }

    void calc_univ_poly_coefficients(std::array<int64_t, N_POLY_TERMS> &result) {
        auto *terms = new std::array<int64_t, N_POLY_TERMS - 1>();

        for (int i = 0; i < PLAIN_MOD; i += 2) {
            int64_t exponent = (i == PLAIN_MOD - 1) ? (PLAIN_MOD - i - 1) : (PLAIN_MOD - i);
            std::for_each(std::execution::par, terms->begin(), terms->end(), [&](int64_t &term) {
                auto a = (&term - &(*terms->begin())) + 1;
                term = mod_exp(a, exponent, PLAIN_MOD);
            });

            result[i/2] = std::accumulate(terms->begin(), terms->end(), 0, mod_sum);
        }

        delete terms;
    }

    void paterson_stockmeyer(gpu::BFVContext &bfv, const std::vector<int64_t> &coefficients, const Ciphertext &z, Ciphertext &result) {
        int k = coefficients.size();
        int s = static_cast<int>(std::sqrt(k));     // Truncate the result to previous integer
        int v = k / s;
        std::cout << "Paterson-Stockmeyer: k = " << k << ", s = " << s << ", v = " << v << std::endl;

        // Precompute powers of z up to z^s.
        // Requires only sqrt(n) exponentiations instead of n
        // Each has a multiplicative depth of roughly log2(2i)
        // Max depth is log2(2s) = log2(2sqrt(k)) = 1 + 0.5log2(k)
        std::vector<Ciphertext> z_powers(s + 1);
        for (int i = 0; i <= s; ++i) {
            z_powers[i] = bfv.encryptor.encrypt_zero_asymmetric_new();
            mod_exp(bfv, z, i, z_powers[i]);
        }
        
        result = bfv.encryptor.encrypt_zero_asymmetric_new();

        // Outer loop: combine blocks, from 0 to v - 1
        for (int i = 0; i < v; ++i) {
            Ciphertext block_result = bfv.encryptor.encrypt_zero_asymmetric_new();

            // Inner loop: evaluate each block, from 0 to s - 1 
            for (int j = 0; j < s; ++j) {
                int idx = i * s + j;
                // If the coefficient is zero, skip calculating the modular exponent
                // Also avoids std::logic_error due to transparent ciphertext
                if (coefficients[idx] != 0) {
                    Plaintext alpha = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), coefficients[idx]));
                    Ciphertext term = z_powers[j];
                    bfv.evaluator.multiply_plain_inplace(term, alpha);
                    bfv.evaluator.relinearize_inplace(term, bfv.relin_keys);
                    bfv.evaluator.add_inplace(block_result, term);
                }
            }

            // Multiply by the outer power (z^(si)) and add to the result
            Ciphertext outer_power;
            mod_exp(bfv, z_powers[s], i, outer_power);
            bfv.evaluator.multiply_inplace(block_result, outer_power);
            bfv.evaluator.relinearize_inplace(block_result, bfv.relin_keys);
            bfv.evaluator.add_inplace(result, block_result);
        }

        // Last block: remainder of k / s
        Ciphertext last_block = bfv.encryptor.encrypt_zero_asymmetric_new();
        for (int j = 0; j < k % s; ++j) {
            int idx = s * v + j;
            if (coefficients[idx] != 0) {
                Plaintext alpha = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), coefficients[idx]));
                Ciphertext term = z_powers[j];
                bfv.evaluator.multiply_plain_inplace(term, alpha);
                bfv.evaluator.relinearize_inplace(term, bfv.relin_keys);
                bfv.evaluator.add_inplace(last_block, term);
            }
        }

        Ciphertext last_power;
        mod_exp(bfv, z_powers[s], v, last_power);
        bfv.evaluator.multiply_inplace(last_block, last_power);
        bfv.evaluator.relinearize_inplace(last_block, bfv.relin_keys);
        bfv.evaluator.add_inplace(result, last_block);
    }

    void lt_univariate(gpu::BFVContext &bfv, const std::array<int64_t, N_POLY_TERMS> &coefficients, const Ciphertext &x, const Ciphertext &y, Ciphertext &result) {
        Ciphertext z = x, y_copy = y;
        if(!z.on_device())
            z.to_device_inplace();
        if(!y_copy.on_device())
            y_copy.to_device_inplace();
        
        bfv.evaluator.sub_inplace(z, y_copy);

        // Evaluate the second term as Zg(Z^2)
        Ciphertext second_term, z2;
        bfv.evaluator.square(z, z2);
        bfv.evaluator.relinearize_inplace(z2, bfv.relin_keys);
        // Evaluate g(X) with X = Z^2 using the Paterson-Stockmeyer algorithm
        paterson_stockmeyer(bfv, std::vector<int64_t>(coefficients.begin(), coefficients.end() - 1), z2, second_term);
        bfv.evaluator.multiply_inplace(second_term, z);
        bfv.evaluator.relinearize_inplace(second_term, bfv.relin_keys);

        // Evaluate the first term
        Ciphertext first_term = bfv.encryptor.encrypt_zero_asymmetric_new();
        Plaintext alpha_zero = bfv.batch_encoder.encode_new(std::vector<uint64_t>(bfv.batch_encoder.slot_count(), coefficients.back()));
        mod_exp(bfv, z, PLAIN_MOD - 1, first_term);
        bfv.evaluator.multiply_plain_inplace(first_term, alpha_zero);
        bfv.evaluator.relinearize_inplace(first_term, bfv.relin_keys);

        bfv.evaluator.add(first_term, second_term, result);
    }
}
