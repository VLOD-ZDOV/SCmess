#ifndef RSA_KEYGEN_H
#define RSA_KEYGEN_H

#ifdef __cplusplus
extern "C" {
    #endif

    int rsa_generate_key_pair_2048(const char *pub_path, const char *priv_path);
    int rsa_generate_key_pair_4096(const char *pub_path, const char *priv_path);

    #ifdef __cplusplus
}
#endif

#endif // RSA_KEYGEN_H
