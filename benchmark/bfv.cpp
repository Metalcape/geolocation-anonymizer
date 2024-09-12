#include "bfv.h"

// namespace seal {
//     bool operator==(const Ciphertext& ctx1, const Ciphertext& ctx2) {
//         return ctx1.parms_id() == ctx2.parms_id() && ctx1.data() == ctx2.data();
//     }
// }

namespace cpu {
    using namespace seal;

    // Constructors
    cpu::BFVContext::BFVContext(const seal::EncryptionParameters &parms) : 
        parms(parms), context(parms), 
        keygen(context), 
        secret_key(keygen.secret_key()), 
        encryptor(context, secret_key), 
        evaluator(context), 
        decryptor(context, secret_key), 
        batch_encoder(context) 
    {
        keygen.create_public_key(this->public_key);
        keygen.create_relin_keys(this->relin_keys);
        this->encryptor.set_public_key(this->public_key);
    }

    // Functions
    EncryptionParameters get_default_parameters() {
        EncryptionParameters parms(scheme_type::bfv);
        size_t poly_modulus_degree = pow(2.0, POLY_MOD_DEG_EXP);

        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        parms.set_plain_modulus(PLAIN_MOD);
        return parms;
    }

    std::vector<Ciphertext> encrypt_data(cpu::BFVContext &bfv, std::vector<std::vector<uint64_t>> data) {
        std::vector<Ciphertext> enc_data(data.size());
        for(int i = 0; i < enc_data.size(); ++i) {
            Plaintext pt;
            Ciphertext ct;
            bfv.batch_encoder.encode(data[i], pt);
            bfv.encryptor.encrypt(pt, ct);
            enc_data[i] = ct;
        }
        return enc_data;
    }

    void mod_exp(cpu::BFVContext &bfv, const Ciphertext &x, uint64_t exponent, Ciphertext &result) {
        Plaintext plain_one("1");
        Ciphertext base(x);
        bfv.encryptor.encrypt(plain_one, result);

        if (exponent == 1) {
            result = x;
            return;
        }

        // Compute modular exponent by square and multiply
        // evaluator.exponentiate_inplace(result, P - 1, relin_keys);
        uint64_t initial_exponent = exponent;
        while (exponent > 0)
        {
            if(exponent % 2 == 1) {
                bfv.evaluator.multiply_inplace(result, base);
                bfv.evaluator.relinearize_inplace(result, bfv.relin_keys);
            }
            exponent >>= 1;
            bfv.evaluator.square_inplace(base);
            bfv.evaluator.relinearize_inplace(base, bfv.relin_keys);
            // std::cout << bfv.decryptor.invariant_noise_budget(base) << std::endl;
        }

        if(bfv.decryptor.invariant_noise_budget(result) <= 0) {
            // std::cout << "mod_exp: out of noise budget while calculating exp(X, " << initial_exponent << ")!" << std::endl;
            std::string err_msg("mod_exp: out of noise budget while calculating exp(X, " + std::to_string(initial_exponent) + ")!");
            throw std::logic_error(err_msg);
            exit(-1);
        }
    }

    void equate_plain(cpu::BFVContext &bfv, const Ciphertext &x, const Plaintext &y, Ciphertext &result) {
        // Equate
        // EQ(x, y) = 1 - (x - y)^p-1

        Plaintext plain_one("1");
        Ciphertext base;
        bfv.evaluator.sub_plain(x, y, base);

        uint64_t exponent = PLAIN_MOD - 1;
        mod_exp(bfv, base, exponent, result);
        bfv.evaluator.negate_inplace(result);
        bfv.evaluator.relinearize_inplace(result, bfv.relin_keys);
        bfv.evaluator.add_plain_inplace(result, plain_one);
    }

    void lt_range(cpu::BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
        // Range comparison from 0 to threshold - 1

        // Equals [i][j] == 1 if x[j] == i, 0 otherwise
        std::vector<Ciphertext> equals(y);

        for(uint64_t i = 0; i < y; ++i) {
            Plaintext ptx(std::to_string(i));
            equate_plain(bfv, x, ptx, equals[i]);
            // print_ciphertext(he, equals[i], 14);
        }

        // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
        bfv.evaluator.add_many(equals, result);
    }

    void lt_range_mt(cpu::BFVContext &bfv, const Ciphertext &x, uint64_t y, Ciphertext &result) {
        // Vector to store results
        std::vector<Ciphertext> equals(y);

        // Loop with concurrent execution
        std::for_each(std::execution::par, equals.begin(), equals.end(), [&](Ciphertext &row) {
            // auto i = std::find(equals.begin(), equals.end(), row) - equals.begin();
            auto i = &row - &equals[0];
            Plaintext ptx(std::to_string(i));
            equate_plain(bfv, x, ptx, row);
        });

        // Sum everything: if x[j] was within [0, y - 1] then result[j] == 1, 0 otherwise
        bfv.evaluator.add_many(equals, result);
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

    void paterson_stockmeyer(cpu::BFVContext &bfv, const std::vector<int64_t> &coefficients, const Ciphertext &z, Ciphertext &result) {
        int k = coefficients.size();
        int s = static_cast<int>(std::sqrt(k));     // Truncate the result to previous integer
        int v = k / s;
        std::cout << "Paterson-Stockmeyer: k = " << k << ", s = " << s << ", v = " << v << std::endl;

        // Precompute powers of z up to z^s.
        // Requires only sqrt(n) exponentiations instead of n
        // Each has a multiplicative depth of roughly log2(2i)
        // Max depth is log2(2s) = log2(2sqrt(k)) = 1 + 0.5log2(k)
        std::vector<Ciphertext> z_powers(s + 1);
        std::for_each(std::execution::par, z_powers.begin(), z_powers.end(), [&](Ciphertext &z_i) {
            auto i = &z_i - &z_powers[0];
            bfv.encryptor.encrypt_zero(z_powers[i]);
            mod_exp(bfv, z, i, z_powers[i]);
        });

        bfv.encryptor.encrypt_zero(result);
        std::vector<Ciphertext> block_results(v);

        // In parallel: combine blocks, from 0 to v - 1
        std::for_each(std::execution::par, block_results.begin(), block_results.end(), [&](Ciphertext &block_result) {
            auto i = &block_result - &block_results[0];
            bfv.encryptor.encrypt_zero(block_result);

            // Inner loop: evaluate each block, from 0 to s - 1 
            for (int j = 0; j < s; ++j) {
                int idx = i * s + j;
                // If the coefficient is zero, skip calculating the modular exponent
                // Also avoids std::logic_error due to transparent ciphertext
                if (coefficients[idx] != 0) {
                    Plaintext alpha(std::to_string(coefficients[idx]));
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
        });

        bfv.evaluator.add_many(block_results, result);

        // Last block: remainder of k / s
        Ciphertext last_block;
        bfv.encryptor.encrypt_zero(last_block);
        for (int j = 0; j < k % s; ++j) {
            int idx = s * v + j;
            if (coefficients[idx] != 0) {
                Plaintext alpha(std::to_string(coefficients[idx]));
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

    void lt_univariate(cpu::BFVContext &bfv, const std::array<int64_t, N_POLY_TERMS> &coefficients, const Ciphertext &x, const Ciphertext &y, Ciphertext &result) {
        Ciphertext z = x;
        bfv.evaluator.sub_inplace(z, y);
        
        Ciphertext second_term, z2;
        bfv.evaluator.square(z, z2);
        bfv.evaluator.relinearize_inplace(z2, bfv.relin_keys);
        paterson_stockmeyer(bfv, std::vector<int64_t>(coefficients.begin(), coefficients.end() - 1), z2, second_term);
        bfv.evaluator.multiply_inplace(second_term, z);
        bfv.evaluator.relinearize_inplace(second_term, bfv.relin_keys);
        
        Ciphertext first_term;
        Plaintext alpha_zero(std::to_string(coefficients.back()));
        mod_exp(bfv, z, PLAIN_MOD - 1, first_term);
        bfv.evaluator.multiply_plain_inplace(first_term, alpha_zero);
        bfv.evaluator.relinearize_inplace(first_term, bfv.relin_keys);

        bfv.evaluator.add(first_term, second_term, result);
    }
}
