#ifndef CCMESS_H
#define CCMESS_H

#ifdef __cplusplus
extern "C" {
    #endif

    int encrypt_text(const char *plaintext, const char *pub_key_path, char **output_b64);
    int decrypt_text(const char *input_b64, const char *priv_key_path, char **output_text);

    int encrypt_file(const char *infile, const char *outfile);
    int decrypt_file(const char *infile, const char *outfile, const char *priv_key_path);

    int generate_key_pair(const char *username, char **pub_path, char **priv_path);
    int generate_key_pair_custom(const char *username, int bits, char **pub_path, char **priv_path);

    int save_keys_to_json(const char *username, const char *pub_path, char *priv_path);

    int delete_user_from_json(const char *username);

    char** scan_for_keys(const char *key_type, int *count);

    #ifdef __cplusplus
}
#endif

#endif // CCMESS_H
