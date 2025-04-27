#include "rsa_keygen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <x86intrin.h>
#endif

#define CACHE_SIZE (32 * 1024)
#define MILLER_RABIN_ITERS 6
#define BITS 2048

static const unsigned small_primes[] = {
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53
};
static const size_t num_small_primes = sizeof(small_primes) / sizeof(small_primes[0]);

static void log_to_file(const char *message) {
    FILE *log_file = fopen("app.log", "a");
    if (log_file) {
        time_t now = time(NULL);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

static void log_error(const char *context, const char *details) {
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "Ошибка в %s: %s", context, details);
    log_to_file(log_msg);
}

static uint64_t get_timer() {
    #ifdef _WIN32
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
    #else
    return __rdtsc();
    #endif
}

static int is_divisible_by_small(mpz_t n) {
    if (mpz_cmp_ui(n, 2) <= 0) return 1;
    if (mpz_even_p(n)) return 1;

    for (size_t i = 0; i < num_small_primes; i++) {
        if (mpz_divisible_ui_p(n, small_primes[i])) return 1;
    }
    return 0;
}

static int is_prime(mpz_t n, int reps, gmp_randstate_t *state) {
    if (mpz_cmp_ui(n, 2) < 0 || mpz_even_p(n) || is_divisible_by_small(n)) {
        return 0;
    }

    mpz_t d, a, x, n_minus_1;
    mpz_inits(d, a, x, n_minus_1, NULL);
    mpz_sub_ui(n_minus_1, n, 1);
    mpz_set(d, n_minus_1);

    int s = 0;
    while (mpz_even_p(d)) {
        mpz_divexact_ui(d, d, 2);
        s++;
    }

    for (int i = 0; i < reps; i++) {
        mpz_urandomm(a, *state, n_minus_1);
        mpz_add_ui(a, a, 1);
        if (mpz_cmp_ui(a, 1) <= 0 || mpz_cmp(a, n_minus_1) >= 0) continue;
        mpz_powm(x, a, d, n);
        if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, n_minus_1) == 0) continue;

        int cont = 0;
        for (int j = 0; j < s; j++) {
            mpz_powm_ui(x, x, 2, n);
            if (mpz_cmp(x, n_minus_1) == 0) {
                cont = 1;
                break;
            }
        }
        if (!cont) {
            mpz_clears(d, a, x, n_minus_1, NULL);
            return 0;
        }
    }

    mpz_clears(d, a, x, n_minus_1, NULL);
    return 1;
}

static void generate_prime(mpz_t prime, int bits) {
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    unsigned long seed = (unsigned)time(NULL) ^ get_timer();
    gmp_randseed_ui(state, seed);

    do {
        mpz_urandomb(prime, state, bits);
        mpz_setbit(prime, bits - 1);
        mpz_setbit(prime, 0);
        if (mpz_cmp_ui(prime, 0) <= 0) continue;
    } while (!is_prime(prime, MILLER_RABIN_ITERS, &state));

        gmp_randclear(state);
}

int rsa_generate_key_pair_2048(const char *pub_path, const char *priv_path) {
    char log_msg[512];
    char *cache_buf = malloc(CACHE_SIZE);
    if (!cache_buf) {
        log_error("rsa_generate_key_pair_2048", "Не удалось выделить память для cache_buf");
        return -2;
    }
    memset(cache_buf, 0, CACHE_SIZE);

    mpz_t p, q, n, phi, e, d, dP, dQ, qInv, p1, q1;
    mpz_inits(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);

    generate_prime(p, BITS / 2);
    generate_prime(q, BITS / 2);

    mpz_mul(n, p, q);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    mpz_set_ui(e, 65537);
    if (mpz_invert(d, e, phi) == 0) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось вычислить приватный ключ d (e=%lu, phi=%s)", 65537UL, mpz_get_str(NULL, 10, phi));
        log_error("rsa_generate_key_pair_2048", log_msg);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -3;
    }

    mpz_mod(dP, d, p1);
    mpz_mod(dQ, d, q1);
    mpz_invert(qInv, q, p);

    BIGNUM *bn_n = BN_new();
    BIGNUM *bn_e = BN_new();
    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *bn_dmp1 = BN_new();
    BIGNUM *bn_dmq1 = BN_new();
    BIGNUM *bn_iqmp = BN_new();
    if (!bn_n || !bn_e || !bn_d || !bn_p || !bn_q || !bn_dmp1 || !bn_dmq1 || !bn_iqmp) {
        log_error("rsa_generate_key_pair_2048", "Не удалось выделить BIGNUM");
        BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
        BN_free(bn_p); BN_free(bn_q); BN_free(bn_dmp1);
        BN_free(bn_dmq1); BN_free(bn_iqmp);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -4;
    }

    BN_dec2bn(&bn_n, mpz_get_str(NULL, 10, n));
    BN_dec2bn(&bn_e, mpz_get_str(NULL, 10, e));
    BN_dec2bn(&bn_d, mpz_get_str(NULL, 10, d));
    BN_dec2bn(&bn_p, mpz_get_str(NULL, 10, p));
    BN_dec2bn(&bn_q, mpz_get_str(NULL, 10, q));
    BN_dec2bn(&bn_dmp1, mpz_get_str(NULL, 10, dP));
    BN_dec2bn(&bn_dmq1, mpz_get_str(NULL, 10, dQ));
    BN_dec2bn(&bn_iqmp, mpz_get_str(NULL, 10, qInv));

    RSA *rsa = RSA_new();
    if (!rsa) {
        log_error("rsa_generate_key_pair_2048", "Не удалось создать RSA структуру");
        BN_free(bn_n); BN_free(bn_e); BN_free(bn_d);
        BN_free(bn_p); BN_free(bn_q); BN_free(bn_dmp1);
        BN_free(bn_dmq1); BN_free(bn_iqmp);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -5;
    }

    if (!RSA_set0_key(rsa, bn_n, bn_e, bn_d)) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось установить ключевые параметры RSA: %s", ERR_error_string(ERR_get_error(), NULL));
        log_error("rsa_generate_key_pair_2048", log_msg);
        RSA_free(rsa);
        BN_free(bn_p); BN_free(bn_q); BN_free(bn_dmp1);
        BN_free(bn_dmq1); BN_free(bn_iqmp);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -7;
    }

    if (!RSA_set0_factors(rsa, bn_p, bn_q)) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось установить факторы RSA: %s", ERR_error_string(ERR_get_error(), NULL));
        log_error("rsa_generate_key_pair_2048", log_msg);
        RSA_free(rsa);
        BN_free(bn_dmp1); BN_free(bn_dmq1); BN_free(bn_iqmp);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -7;
    }

    if (!RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp)) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось установить CRT параметры RSA: %s", ERR_error_string(ERR_get_error(), NULL));
        log_error("rsa_generate_key_pair_2048", log_msg);
        RSA_free(rsa);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -7;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        log_error("rsa_generate_key_pair_2048", "Не удалось создать EVP_PKEY");
        RSA_free(rsa);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -5;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось присвоить RSA ключ EVP_PKEY: %s", ERR_error_string(ERR_get_error(), NULL));
        log_error("rsa_generate_key_pair_2048", log_msg);
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -6;
    }

    FILE *pub_file = fopen(pub_path, "wb");
    FILE *priv_file = fopen(priv_path, "wb");
    if (!pub_file || !priv_file) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось открыть файлы: pub=%s, priv=%s", pub_path, priv_path);
        log_error("rsa_generate_key_pair_2048", log_msg);
        fclose(pub_file);
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -8;
    }

    if (!PEM_write_PUBKEY(pub_file, pkey) || !PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        snprintf(log_msg, sizeof(log_msg), "Не удалось записать ключи в PEM файлы: %s", ERR_error_string(ERR_get_error(), NULL));
        log_error("rsa_generate_key_pair_2048", log_msg);
        fclose(pub_file);
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        free(cache_buf);
        mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);
        return -9;
    }

    fclose(pub_file);
    fclose(priv_file);
    EVP_PKEY_free(pkey);
    free(cache_buf);
    mpz_clears(p, q, n, phi, e, d, dP, dQ, qInv, p1, q1, NULL);

    snprintf(log_msg, sizeof(log_msg), "Ключи сгенерированы (2048 бит): Публичный=%s, Приватный=%s", pub_path, priv_path);
    log_to_file(log_msg);
    return 0;
}
