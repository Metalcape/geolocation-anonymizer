#pragma once

/*
    The exponent of poly_modulus_degree as a power of 2.
    poly_modulus_degree is equal to the order of the multiplicative group defined by 
    the cyclotomic polynomial of degree m, such that phi(m) = poly_modulus_degree.
    Higher values increase noise budget at the cost of performance.
    It is also equal to the number of ciphertext slots when batching is enabled.
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
*/
#define PLAIN_MOD 65537

/*
    The number of terms in the univariate comparison polynomial.
    Effectively equal to the number of even numbers from 0 to p-1.
*/
#define N_POLY_TERMS PLAIN_MOD/2+1
