#include "libbfv.h"
#include <vector>

using namespace seal;

int main() {
    /* Create encryption context */
    EncryptionParameters parms = get_default_parameters();
    BFVContext bfv(parms);

    std::vector<std::vector<uint64_t>> data = {
        {1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0},
        {1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0},
        {1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0},
        {1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0},
        {1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0},
        {0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0},
        {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
        {1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0},
        {0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},
        {1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0},
        {0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0}
    };

    std::cout << "Plaintext sample: " << std::endl;
    for(uint64_t i: data[0])
        std::cout << i << ' ';
    std::cout << std::endl;

    std::vector<Ciphertext> enc_data = encrypt_data(bfv, data);

    size_t ctx_n = data[0].size();
    std::cout << "Decrypted ciphertext sample: " << std::endl;
    print_ciphertext(bfv, enc_data[0], ctx_n);

    // Sum everything
    std::cout << "Aggregate: " << std::endl;
    Ciphertext aggregate;
    bfv.evaluator.add_many(enc_data, aggregate);
    print_ciphertext(bfv, aggregate, ctx_n);

    // Filter
    std::cout << "Filtered: " << std::endl;
    Ciphertext filtered;
    bfv.evaluator.multiply(enc_data[0], aggregate, filtered);
    bfv.evaluator.relinearize_inplace(filtered, bfv.relin_keys);
    print_ciphertext(bfv, filtered, ctx_n);

    // Equate test
    std::cout << "EQ test: " << std::endl;
    Plaintext eq_test("6");
    Ciphertext eq;
    equate_plain(bfv, filtered, eq_test, eq);
    print_ciphertext(bfv, eq, ctx_n);

    // Range comparison from o to threshold - 1
    uint64_t threshold = 10;
    std::cout << "Lower than " << threshold << ": " << std::endl;
    Ciphertext gt;
    lt_range(bfv, filtered, threshold, gt);
    print_ciphertext(bfv, gt, ctx_n);
}