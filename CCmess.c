#include "CCmess.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <cjson/cJSON.h>

#define AES_KEYLEN 32
#define GCM_IVLEN 12
#define GCM_TAGLEN 16
#define KEYS_FILE "keys.json"

// Вспомогательная функция для кодирования в Base64
static char* base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    char *output = (char *)malloc(buffer_ptr->length + 1);
    memcpy(output, buffer_ptr->data, buffer_ptr->length);
    output[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return output;
}

// Вспомогательная функция для декодирования из Base64
static unsigned char* base64_decode(const char *input, int *out_length) {
    BIO *bio, *b64;
    int len = strlen(input);
    unsigned char *output = (unsigned char *)malloc(len);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_length = BIO_read(bio, output, len);
    output[*out_length] = '\0';

    BIO_free_all(bio);
    return output;
}

int generate_key_pair(const char *username, char **pub_path, char **priv_path) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
    return -1;
        }

        // Получаем текущую временную метку в формате YYYYMMDDHHMMSS
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timestamp[15];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", t);

        // Формируем имена файлов
        *pub_path = malloc(strlen(username) + 25); // RSA_{username}_pub_{timestamp}.pem
        *priv_path = malloc(strlen(username) + 26); // RSA_{username}_priv_{timestamp}.pem
        sprintf(*pub_path, "RSA_%s_pub_%s.pem", username, timestamp);
        sprintf(*priv_path, "RSA_%s_priv_%s.pem", username, timestamp);

        FILE *pub_file = fopen(*pub_path, "wb");
        FILE *priv_file = fopen(*priv_path, "wb");
        if (!pub_file || !priv_file) {
            free(*pub_path);
            free(*priv_path);
            fclose(pub_file);
            fclose(priv_file);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            return -2;
        }

        PEM_write_PUBKEY(pub_file, pkey);
        PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL);

        fclose(pub_file);
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 0;
}

int save_keys_to_json(const char *username, const char *pub_path, const char *priv_path) {
    FILE *f = fopen(KEYS_FILE, "r+");
    cJSON *root = NULL;

    if (f) {
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *data = malloc(len + 1);
        fread(data, 1, len, f);
        data[len] = '\0';
        root = cJSON_Parse(data);
        free(data);
        fclose(f);
    } else {
        root = cJSON_CreateArray();
    }

    cJSON *new_entry = cJSON_CreateObject();
    cJSON_AddStringToObject(new_entry, "username", username);
    cJSON_AddStringToObject(new_entry, "public_key_path", pub_path);
    cJSON_AddStringToObject(new_entry, "private_key_path", priv_path);
    cJSON_AddItemToArray(root, new_entry);

    f = fopen(KEYS_FILE, "w");
    char *json = cJSON_Print(root);
    fwrite(json, 1, strlen(json), f);
    fclose(f);

    cJSON_Delete(root);
    free(json);
    return 0;
}

char** scan_for_keys(const char *key_type, int *count) {
    DIR *dir;
    struct dirent *ent;
    char **results = malloc(sizeof(char*) * 20);
    *count = 0;

    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (strstr(ent->d_name, ".pem")) {
                if (strcmp(key_type, "public") == 0 && strstr(ent->d_name, "RSA_") && strstr(ent->d_name, "_pub_")) {
                    results[*count] = strdup(ent->d_name);
                    (*count)++;
                } else if (strcmp(key_type, "private") == 0 && strstr(ent->d_name, "RSA_") && strstr(ent->d_name, "_priv_")) {
                    results[*count] = strdup(ent->d_name);
                    (*count)++;
                }
            }
        }
        closedir(dir);
    }
    return results;
}

int encrypt_text(const char *plaintext, const char *pub_key_path, char **output_b64) {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[AES_KEYLEN];
    unsigned char iv[GCM_IVLEN];
    unsigned char tag[GCM_TAGLEN];
    int len, ciphertext_len;

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) return -1;

    unsigned char *ciphertext = malloc(strlen(plaintext) + AES_KEYLEN);
    if (!ciphertext) return -2;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        return -3;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IVLEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, strlen(plaintext));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAGLEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Чтение публичного ключа RSA
    FILE *pub_file = fopen(pub_key_path, "r");
    if (!pub_file) {
        free(ciphertext);
        return -4;
    }
    EVP_PKEY *pub_key = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);
    if (!pub_key) {
        free(ciphertext);
        return -5;
    }

    // Шифрование ключа AES с помощью RSA
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!pctx || EVP_PKEY_encrypt_init(pctx) <= 0) {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_CTX_free(pctx);
        free(ciphertext);
        return -6;
    }

    // Устанавливаем режим RSA_PKCS1_PADDING (по умолчанию)
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_CTX_free(pctx);
        free(ciphertext);
        return -7;
    }

    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(pctx, NULL, &encrypted_key_len, key, AES_KEYLEN) <= 0) {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_CTX_free(pctx);
        free(ciphertext);
        return -8;
    }

    unsigned char *encrypted_key = malloc(encrypted_key_len);
    if (EVP_PKEY_encrypt(pctx, encrypted_key, &encrypted_key_len, key, AES_KEYLEN) <= 0) {
        EVP_PKEY_free(pub_key);
        EVP_PKEY_CTX_free(pctx);
        free(ciphertext);
        free(encrypted_key);
        return -9;
    }

    // Кодируем в Base64
    char *encrypted_key_b64 = base64_encode(encrypted_key, encrypted_key_len);
    char *iv_b64 = base64_encode(iv, GCM_IVLEN);
    char *tag_b64 = base64_encode(tag, GCM_TAGLEN);
    char *data_b64 = base64_encode(ciphertext, ciphertext_len);

    // Создаем JSON
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "key", encrypted_key_b64);
    cJSON_AddStringToObject(root, "iv", iv_b64);
    cJSON_AddStringToObject(root, "tag", tag_b64);
    cJSON_AddStringToObject(root, "data", data_b64);

    char *json = cJSON_PrintUnformatted(root);
    *output_b64 = json;

    free(encrypted_key_b64);
    free(iv_b64);
    free(tag_b64);
    free(data_b64);
    free(ciphertext);
    free(encrypted_key);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_CTX_free(pctx);
    cJSON_Delete(root);

    return 0;
}

int decrypt_text(const char *input_b64, const char *priv_key_path, char **output_text) {
    cJSON *root = cJSON_Parse(input_b64);
    if (!root) return -1;

    const char *encrypted_key_b64 = cJSON_GetObjectItem(root, "key")->valuestring;
    const char *iv_b64 = cJSON_GetObjectItem(root, "iv")->valuestring;
    const char *tag_b64 = cJSON_GetObjectItem(root, "tag")->valuestring;
    const char *data_b64 = cJSON_GetObjectItem(root, "data")->valuestring;

    int encrypted_key_len, iv_len, tag_len, data_len;
    unsigned char *encrypted_key = base64_decode(encrypted_key_b64, &encrypted_key_len);
    unsigned char *iv = base64_decode(iv_b64, &iv_len);
    unsigned char *tag = base64_decode(tag_b64, &tag_len);
    unsigned char *ciphertext = base64_decode(data_b64, &data_len);

    // Чтение приватного ключа RSA
    FILE *priv_file = fopen(priv_key_path, "r");
    if (!priv_file) {
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        cJSON_Delete(root);
        return -4;
    }
    EVP_PKEY *priv_key = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);
    if (!priv_key) {
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        cJSON_Delete(root);
        return -5;
    }

    // Расшифровка ключа AES
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!pctx || EVP_PKEY_decrypt_init(pctx) <= 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        cJSON_Delete(root);
        return -6;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        cJSON_Delete(root);
        return -7;
    }

    size_t key_len;
    if (EVP_PKEY_decrypt(pctx, NULL, &key_len, encrypted_key, encrypted_key_len) <= 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        cJSON_Delete(root);
        return -8;
    }

    unsigned char *key = malloc(key_len);
    if (EVP_PKEY_decrypt(pctx, key, &key_len, encrypted_key, encrypted_key_len) <= 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        free(key);
        cJSON_Delete(root);
        return -9;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        free(key);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        cJSON_Delete(root);
        return -3;
    }

    int len, plaintext_len;
    unsigned char *plaintext = malloc(data_len + 1);

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IVLEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, data_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAGLEN, tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        free(encrypted_key); free(iv); free(tag); free(ciphertext);
        free(plaintext);
        free(key);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_CTX_free(pctx);
        EVP_CIPHER_CTX_free(ctx);
        cJSON_Delete(root);
        return -2;
    }

    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    *output_text = (char*)plaintext;

    free(encrypted_key);
    free(iv);
    free(tag);
    free(ciphertext);
    free(key);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_CTX_free(pctx);
    EVP_CIPHER_CTX_free(ctx);
    cJSON_Delete(root);
    return 0;
}

int encrypt_file(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    if (!in) return -1;

    fseek(in, 0, SEEK_END);
    size_t fsize = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char *buffer = malloc(fsize + 1);
    fread(buffer, 1, fsize, in);
    buffer[fsize] = '\0';
    fclose(in);

    // Временное решение: используем первый публичный ключ из keys.json
    // В идеале это должен быть выбор пользователя
    FILE *keys_file = fopen(KEYS_FILE, "r");
    if (!keys_file) {
        free(buffer);
        return -2;
    }
    fseek(keys_file, 0, SEEK_END);
    long keys_len = ftell(keys_file);
    fseek(keys_file, 0, SEEK_SET);
    char *keys_data = malloc(keys_len + 1);
    fread(keys_data, 1, keys_len, keys_file);
    keys_data[keys_len] = '\0';
    fclose(keys_file);

    cJSON *root = cJSON_Parse(keys_data);
    free(keys_data);
    if (!root || !cJSON_IsArray(root) || cJSON_GetArraySize(root) == 0) {
        free(buffer);
        cJSON_Delete(root);
        return -3;
    }

    cJSON *first_key = cJSON_GetArrayItem(root, 0);
    const char *pub_key_path = cJSON_GetObjectItem(first_key, "public_key_path")->valuestring;

    char *encoded = NULL;
    if (encrypt_text((char*)buffer, pub_key_path, &encoded) != 0) {
        free(buffer);
        cJSON_Delete(root);
        return -4;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) {
        free(buffer);
        free(encoded);
        cJSON_Delete(root);
        return -5;
    }

    fwrite(encoded, 1, strlen(encoded), out);
    fclose(out);
    free(buffer);
    free(encoded);
    cJSON_Delete(root);
    return 0;
}

int decrypt_file(const char *infile, const char *outfile, const char *priv_key_path) {
    FILE *in = fopen(infile, "rb");
    if (!in) return -1;

    fseek(in, 0, SEEK_END);
    size_t fsize = ftell(in);
    fseek(in, 0, SEEK_SET);

    char *buffer = malloc(fsize + 1);
    fread(buffer, 1, fsize, in);
    buffer[fsize] = '\0';
    fclose(in);

    char *decoded = NULL;
    if (decrypt_text(buffer, priv_key_path, &decoded) != 0) {
        free(buffer);
        return -2;
    }

    FILE *out = fopen(outfile, "wb");
    if (!out) {
        free(buffer);
        free(decoded);
        return -3;
    }
    fwrite(decoded, 1, strlen(decoded), out);
    fclose(out);
    free(buffer);
    free(decoded);
    return 0;
}

int delete_user_from_json(const char *username) {
    FILE *f = fopen(KEYS_FILE, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) return -2;

    cJSON *new_array = cJSON_CreateArray();
    cJSON *item;
    cJSON_ArrayForEach(item, root) {
        cJSON *user = cJSON_GetObjectItem(item, "username");
        if (user && strcmp(user->valuestring, username) != 0) {
            cJSON_AddItemToArray(new_array, cJSON_Duplicate(item, 1));
        }
    }

    f = fopen(KEYS_FILE, "w");
    char *json = cJSON_Print(new_array);
    fwrite(json, 1, strlen(json), f);
    fclose(f);

    cJSON_Delete(root);
    cJSON_Delete(new_array);
    free(json);
    return 0;
}
