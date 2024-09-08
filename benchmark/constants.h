#pragma once

/*
    The exponent of poly_modulus_degree as a power of 2.
    poly_modulus_degree is equal to the order of the multiplicative group defined by 
    the cyclotomic polynomial of degree m, such that phi(m) = poly_modulus_degree.
    Higher values increase noise budget at the cost of performance.
    It is also equal to the number of ciphertext slots when batching is enabled.
    For the BFV scheme, a minimum value of 2^12 is needed for keyswitching.
*/
#define POLY_MOD_DEG_EXP 15

/*
    Each plaintext slot is encoded as an integer modulo plain_modulus.
    To enable batching, the following must hold:
        - plain_modulus is prime
        - plain_modulus = 1 mod 2*phi(m)
    Larger values expand the plaintext space, but reduce performance, especially when
    it is necessary to apply Fermat's little theorem, which requires a modular exponent
    equal to plain_modulus - 1.

    This table shows the smallest plain_modulus that enables batching for various
    values of poly_modulus_degree:

    +------------------------------------------------------+
    | poly_modulus_degree | min plain_modulus for batching |
    +---------------------+--------------------------------+
    | 1024                | 12289                          |
    | 2048                | 12289                          |
    | 4096                | 40961                          |
    | 8192                | 65537                          |
    | 16384               | 65537                          |
    | 32768               | 65537                          |
    +---------------------+--------------------------------+

    Note that if you use phi(m) < 2^12, you need to manually specify the coeff_modulus
    prime numbers in order to use keyswitching, because otherwise you would have
    only one prime number; therefore you cannot use CoeffModulus::BFVDefault.
*/
#define PLAIN_MOD 65537
static_assert(PLAIN_MOD % (1 << POLY_MOD_DEG_EXP + 1) == 1, "The specified PLAIN_MOD is invalid for batching.");

/*
    The number of terms in the univariate comparison polynomial.
    Effectively equal to the number of even numbers from 0 to p-1.
*/
#define N_POLY_TERMS PLAIN_MOD/2+1
