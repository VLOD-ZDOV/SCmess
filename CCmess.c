// Компиляция для Linux:
// gcc CCmess.c -o CCmess.bin -lssl -lcrypto -lcjson
// Для Windows необходимо правильно настроить пути к OpenSSL и cJSON.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <cjson/cJSON.h>  

// Размеры констант
#define AES_KEYLEN 32   // 256 бит
#define GCM_IVLEN 12
#define GCM_TAGLEN 16
#define RSA_KEYLEN 4096

// Функция для base64-кодирования (для текстового шифрования)
char *base64_encode(const unsigned char *buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    char *b64text = malloc(bufferPtr->length + 1);
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';
    BIO_free_all(bio);
    return b64text;
}

unsigned char *base64_decode(const char *b64message, size_t *out_len) {
    BIO *bio, *b64;
    int decodeLen = strlen(b64message);
    unsigned char *buffer = malloc(decodeLen);
    memset(buffer, 0, decodeLen);
    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    *out_len = BIO_read(bio, buffer, decodeLen);
    BIO_free_all(bio);
    return buffer;
}

// Получение директорий для хранения ключей (упрощённо)
const char *get_private_key_directory() {
    #ifdef _WIN32
    return getenv("USERPROFILE");
    #else
    return getenv("HOME");
    #endif
}

const char *get_public_key_directory() {
    #ifdef _WIN32
    return getenv("USERPROFILE");
    #else
    return getenv("HOME");
    #endif
}

// Получение текущего времени в формате YYYYMMDDHHMMSS
void get_current_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y%m%d%H%M%S", tm_info);
}

/* ============================================================================
 *   Генерация RSA-ключевой пары с использованием нового EVP API
 * ============================================================================ */
int generate_key_pair(const char *username, char **priv_filename, char **pub_filename) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Ошибка создания контекста EVP.\n");
        return -1;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Ошибка инициализации генерации ключа.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
        fprintf(stderr, "Ошибка установки длины RSA ключа.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Ошибка генерации RSA ключа.\n");
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    char timestamp[20];
    get_current_timestamp(timestamp, sizeof(timestamp));
    char priv_path[512], pub_path[512];
    snprintf(priv_path, sizeof(priv_path), "%s/RSA_%s_priv_%s.pem", get_private_key_directory(), username, timestamp);
    snprintf(pub_path, sizeof(pub_path), "%s/RSA_%s_pub_%s.pem", get_public_key_directory(), username, timestamp);

    FILE *fp = fopen(priv_path, "wb");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть файл для записи приватного ключа.\n");
        ret = -1;
        goto cleanup;
    }
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Ошибка записи приватного ключа.\n");
        fclose(fp);
        ret = -1;
        goto cleanup;
    }
    fclose(fp);

    fp = fopen(pub_path, "wb");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть файл для записи публичного ключа.\n");
        ret = -1;
        goto cleanup;
    }
    if (!PEM_write_PUBKEY(fp, pkey)) {
        fprintf(stderr, "Ошибка записи публичного ключа.\n");
        fclose(fp);
        ret = -1;
        goto cleanup;
    }
    fclose(fp);

    *priv_filename = strdup(priv_path);
    *pub_filename = strdup(pub_path);
    printf("Приватный ключ сохранен в: %s\n", priv_path);
    printf("Публичный ключ сохранен в: %s\n", pub_path);

    cleanup:
    EVP_PKEY_free(pkey);
    return ret;
}

/* ============================================================================
 *   Сохранение информации о ключах в JSON с использованием cJSON
 * ============================================================================ */
int save_keys_to_json(const char *username, const char *pub_filename, const char *priv_filename, const char *json_file) {
    FILE *fp = fopen(json_file, "r");
    cJSON *json_root = NULL;
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        char *data = malloc(fsize + 1);
        fread(data, 1, fsize, fp);
        data[fsize] = '\0';
        fclose(fp);
        json_root = cJSON_Parse(data);
        free(data);
    }
    if (!json_root) {
        json_root = cJSON_CreateArray();
    } else if (!cJSON_IsArray(json_root)) {
        cJSON *tmp = cJSON_CreateArray();
        cJSON_AddItemToArray(tmp, json_root);
        json_root = tmp;
    }
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "username", username);
    cJSON_AddStringToObject(entry, "public_key_path", pub_filename);
    cJSON_AddStringToObject(entry, "private_key_path", priv_filename);
    cJSON_AddItemToArray(json_root, entry);

    fp = fopen(json_file, "w");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть JSON файл для записи.\n");
        cJSON_Delete(json_root);
        return -1;
    }
    char *rendered = cJSON_Print(json_root);
    fprintf(fp, "%s", rendered);
    fclose(fp);
    free(rendered);
    cJSON_Delete(json_root);
    return 0;
}

/* ============================================================================
 *   Функция чтения файла в буфер (бинарное чтение)
 * ============================================================================ */
unsigned char *read_file(const char *filepath, size_t *out_len) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *buffer = malloc(fsize);
    fread(buffer, 1, fsize, fp);
    fclose(fp);
    *out_len = fsize;
    return buffer;
}

/* ============================================================================
 *   RSA-обёртка: шифрование AES-ключа с использованием нового EVP API
 * ============================================================================ */
unsigned char *rsa_encrypt_aes_key(const char *pub_key_path, unsigned char *aes_key, size_t aes_key_len, size_t *out_len) {
    FILE *fp = fopen(pub_key_path, "rb");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть публичный ключ.\n");
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Ошибка загрузки публичного ключа.\n");
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    // Первый вызов для определения размера выходного буфера
    if (EVP_PKEY_encrypt(ctx, NULL, out_len, aes_key, aes_key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    unsigned char *out = malloc(*out_len);
    if (EVP_PKEY_encrypt(ctx, out, out_len, aes_key, aes_key_len) <= 0) {
        free(out);
        out = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return out;
}

/* ============================================================================
 *   RSA-обёртка: дешифрование AES-ключа с использованием нового EVP API
 * ============================================================================ */
int rsa_decrypt_aes_key(const char *priv_key_path, unsigned char *encrypted_key, size_t encrypted_key_len,
                        unsigned char *aes_key, size_t *aes_key_len) {
    FILE *fp = fopen(priv_key_path, "rb");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть приватный ключ.\n");
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        fprintf(stderr, "Ошибка загрузки приватного ключа.\n");
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    // Определяем длину расшифрованного ключа
    if (EVP_PKEY_decrypt(ctx, NULL, aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_decrypt(ctx, aes_key, aes_key_len, encrypted_key, encrypted_key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
                        }

                        /* ============================================================================
                         *   Шифрование текста с использованием AES-GCM и RSA-обёртки AES-ключа.
                         *   Возвращает cJSON-объект с base64-строками.
                         * ============================================================================ */
                        cJSON *encrypt_text_gcm(const char *pub_key_path, const char *plaintext) {
                            unsigned char aes_key[AES_KEYLEN];
                            unsigned char iv[GCM_IVLEN];
                            if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv))) {
                                fprintf(stderr, "Ошибка генерации случайных байт.\n");
                                return NULL;
                            }

                            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                            int len, ciphertext_len;
                            size_t plaintext_len = strlen(plaintext);
                            unsigned char *ciphertext = malloc(plaintext_len + 16);
                            if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                                fprintf(stderr, "Ошибка инициализации шифрования.\n");
                                return NULL;
                            }
                            if (!EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
                                fprintf(stderr, "Ошибка установки ключа/IV.\n");
                                return NULL;
                            }
                            if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len)) {
                                fprintf(stderr, "Ошибка шифрования текста.\n");
                                return NULL;
                            }
                            ciphertext_len = len;
                            if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                                fprintf(stderr, "Ошибка завершения шифрования.\n");
                                return NULL;
                            }
                            ciphertext_len += len;
                            unsigned char tag[GCM_TAGLEN];
                            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAGLEN, tag);
                            EVP_CIPHER_CTX_free(ctx);

                            // Шифрование AES ключа с использованием RSA нового API
                            size_t encrypted_key_len = 0;
                            unsigned char *encrypted_key = rsa_encrypt_aes_key(pub_key_path, aes_key, sizeof(aes_key), &encrypted_key_len);
                            if (!encrypted_key) {
                                fprintf(stderr, "Ошибка шифрования AES ключа.\n");
                                free(ciphertext);
                                return NULL;
                            }

                            // Формирование JSON-объекта с base64-строками
                            cJSON *json = cJSON_CreateObject();
                            char *b64_encrypted_key = base64_encode(encrypted_key, encrypted_key_len);
                            char *b64_iv = base64_encode(iv, sizeof(iv));
                            char *b64_tag = base64_encode(tag, sizeof(tag));
                            char *b64_ciphertext = base64_encode(ciphertext, ciphertext_len);
                            cJSON_AddStringToObject(json, "aes_key", b64_encrypted_key);
                            cJSON_AddStringToObject(json, "iv", b64_iv);
                            cJSON_AddStringToObject(json, "tag", b64_tag);
                            cJSON_AddStringToObject(json, "ciphertext", b64_ciphertext);

                            free(b64_encrypted_key);
                            free(b64_iv);
                            free(b64_tag);
                            free(b64_ciphertext);
                            free(encrypted_key);
                            free(ciphertext);
                            return json;
                        }

                        /* ============================================================================
                         *   Дешифрование текста с использованием AES-GCM и RSA-распаковки AES-ключа.
                         *   Для ввода многострочного текста используется функция get_multiline_input.
                         * ============================================================================ */
                        char *decrypt_text_gcm(const char *priv_key_path, cJSON *json) {
                            cJSON *aes_key_item = cJSON_GetObjectItemCaseSensitive(json, "aes_key");
                            cJSON *iv_item = cJSON_GetObjectItemCaseSensitive(json, "iv");
                            cJSON *tag_item = cJSON_GetObjectItemCaseSensitive(json, "tag");
                            cJSON *ciphertext_item = cJSON_GetObjectItemCaseSensitive(json, "ciphertext");
                            if (!cJSON_IsString(aes_key_item) || !cJSON_IsString(iv_item) ||
                                !cJSON_IsString(tag_item) || !cJSON_IsString(ciphertext_item)) {
                                fprintf(stderr, "Неверный формат JSON.\n");
                            return NULL;
                                }
                                size_t enc_key_len, iv_len, tag_len, ciphertext_len;
                                unsigned char *encrypted_key = base64_decode(aes_key_item->valuestring, &enc_key_len);
                                unsigned char *iv = base64_decode(iv_item->valuestring, &iv_len);
                                unsigned char *tag = base64_decode(tag_item->valuestring, &tag_len);
                                unsigned char *ciphertext = base64_decode(ciphertext_item->valuestring, &ciphertext_len);

                                unsigned char aes_key[AES_KEYLEN];
                                size_t aes_key_len = sizeof(aes_key);
                                if (rsa_decrypt_aes_key(priv_key_path, encrypted_key, enc_key_len, aes_key, &aes_key_len) != 0) {
                                    fprintf(stderr, "Ошибка дешифрования AES ключа.\n");
                                    return NULL;
                                }

                                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                                if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                                    fprintf(stderr, "Ошибка инициализации дешифрования.\n");
                                    return NULL;
                                }
                                if (!EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
                                    fprintf(stderr, "Ошибка установки ключа/IV для дешифрования.\n");
                                    return NULL;
                                }
                                EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);
                                unsigned char *plaintext = malloc(ciphertext_len + 1);
                                int len, plaintext_len;
                                if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
                                    fprintf(stderr, "Ошибка дешифрования текста.\n");
                                    return NULL;
                                }
                                plaintext_len = len;
                                if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
                                    fprintf(stderr, "Ошибка завершения дешифрования (возможно, неверный ключ или данные повреждены).\n");
                                    EVP_CIPHER_CTX_free(ctx);
                                    free(plaintext);
                                    return NULL;
                                }
                                plaintext_len += len;
                                plaintext[plaintext_len] = '\0';
                                EVP_CIPHER_CTX_free(ctx);

                                free(encrypted_key);
                                free(iv);
                                free(tag);
                                free(ciphertext);
                                return (char *)plaintext;
                        }

                        /* ============================================================================
                         *   Функции для многострочного ввода: читают строки до появления строки "EOF"
                         * ============================================================================ */
                        char *get_multiline_input() {
                            printf("Введите текст (для завершения ввода введите строку \"EOF\" на новой строке):\n");
                            size_t capacity = 1024;
                            char *buffer = malloc(capacity);
                            buffer[0] = '\0';
                            char line[512];
                            while (fgets(line, sizeof(line), stdin)) {
                                if (strncmp(line, "EOF", 3) == 0)
                                    break;
                                if (strlen(buffer) + strlen(line) + 1 > capacity) {
                                    capacity *= 2;
                                    buffer = realloc(buffer, capacity);
                                }
                                strcat(buffer, line);
                            }
                            return buffer;
                        }

                        /* ============================================================================
                         *   Шифрование файла с использованием AES-GCM и RSA-обёртки AES-ключа.
                         *   Результат записывается в бинарный файл со структурой:
                         *   [uint32_t: длина зашифрованного AES-ключа][AES-ключ][iv (12 байт)][tag (16 байт)]
                         *   [uint32_t: длина ciphertext][ciphertext]
                         * ============================================================================ */
                        int encrypt_file_gcm(const char *pub_key_path, const char *file_path, char *encrypted_file_path, size_t path_size) {
                            size_t file_len;
                            unsigned char *plaintext = read_file(file_path, &file_len);
                            if (!plaintext) {
                                fprintf(stderr, "Не удалось прочитать файл для шифрования.\n");
                                return -1;
                            }
                            unsigned char aes_key[AES_KEYLEN], iv[GCM_IVLEN];
                            if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv))) {
                                fprintf(stderr, "Ошибка генерации случайных байт.\n");
                                free(plaintext);
                                return -1;
                            }
                            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                            int len, ciphertext_len;
                            unsigned char *ciphertext = malloc(file_len + 16);
                            if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                                fprintf(stderr, "Ошибка инициализации шифрования файла.\n");
                                free(plaintext);
                                return -1;
                            }
                            if (!EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
                                fprintf(stderr, "Ошибка установки ключа/IV для файла.\n");
                                free(plaintext);
                                return -1;
                            }
                            if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, file_len)) {
                                fprintf(stderr, "Ошибка шифрования файла.\n");
                                free(plaintext);
                                return -1;
                            }
                            ciphertext_len = len;
                            if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                                fprintf(stderr, "Ошибка завершения шифрования файла.\n");
                                free(plaintext);
                                return -1;
                            }
                            ciphertext_len += len;
                            unsigned char tag[GCM_TAGLEN];
                            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAGLEN, tag);
                            EVP_CIPHER_CTX_free(ctx);
                            free(plaintext);

                            // Шифрование AES ключа с RSA
                            size_t encrypted_key_len = 0;
                            unsigned char *encrypted_key = rsa_encrypt_aes_key(pub_key_path, aes_key, sizeof(aes_key), &encrypted_key_len);
                            if (!encrypted_key) {
                                fprintf(stderr, "Ошибка шифрования AES ключа.\n");
                                free(ciphertext);
                                return -1;
                            }

                            // Открываем файл для записи в бинарном режиме
                            snprintf(encrypted_file_path, path_size, "%s.enc", file_path);
                            FILE *fp = fopen(encrypted_file_path, "wb");
                            if (!fp) {
                                fprintf(stderr, "Не удалось создать файл зашифрованных данных.\n");
                                free(encrypted_key);
                                free(ciphertext);
                                return -1;
                            }
                            // Записываем длину зашифрованного ключа
                            uint32_t ek_len = (uint32_t)encrypted_key_len;
                            fwrite(&ek_len, sizeof(uint32_t), 1, fp);
                            fwrite(encrypted_key, 1, encrypted_key_len, fp);
                            fwrite(iv, 1, sizeof(iv), fp);
                            fwrite(tag, 1, sizeof(tag), fp);
                            uint32_t ct_len = (uint32_t)ciphertext_len;
                            fwrite(&ct_len, sizeof(uint32_t), 1, fp);
                            fwrite(ciphertext, 1, ciphertext_len, fp);
                            fclose(fp);
                            free(encrypted_key);
                            free(ciphertext);
                            return 0;
                        }

                        /* ============================================================================
                         *   Расшифрование файла, созданного функцией encrypt_file_gcm.
                         *   Извлекается бинарная структура и производится дешифрование.
                         * ============================================================================ */
                        int decrypt_file_gcm(const char *priv_key_path, const char *encrypted_file_path, char *decrypted_file_path, size_t path_size) {
                            size_t file_len;
                            unsigned char *data = read_file(encrypted_file_path, &file_len);
                            if (!data) {
                                fprintf(stderr, "Не удалось прочитать зашифрованный файл.\n");
                                return -1;
                            }
                            unsigned char *ptr = data;
                            if (file_len < sizeof(uint32_t)) {
                                fprintf(stderr, "Неверный формат файла.\n");
                                free(data);
                                return -1;
                            }
                            uint32_t ek_len;
                            memcpy(&ek_len, ptr, sizeof(uint32_t));
                            ptr += sizeof(uint32_t);
                            if (file_len < sizeof(uint32_t) + ek_len + GCM_IVLEN + GCM_TAGLEN + sizeof(uint32_t)) {
                                fprintf(stderr, "Неверный формат файла.\n");
                                free(data);
                                return -1;
                            }
                            unsigned char *encrypted_key = ptr;
                            ptr += ek_len;
                            unsigned char iv[GCM_IVLEN];
                            memcpy(iv, ptr, GCM_IVLEN);
                            ptr += GCM_IVLEN;
                            unsigned char tag[GCM_TAGLEN];
                            memcpy(tag, ptr, GCM_TAGLEN);
                            ptr += GCM_TAGLEN;
                            uint32_t ct_len;
                            memcpy(&ct_len, ptr, sizeof(uint32_t));
                            ptr += sizeof(uint32_t);
                            if ((ptr - data) + ct_len > file_len) {
                                fprintf(stderr, "Неверный формат файла: длина ciphertext превышает размер файла.\n");
                                free(data);
                                return -1;
                            }
                            unsigned char *ciphertext = ptr;

                            unsigned char aes_key[AES_KEYLEN];
                            size_t aes_key_len = sizeof(aes_key);
                            if (rsa_decrypt_aes_key(priv_key_path, encrypted_key, ek_len, aes_key, &aes_key_len) != 0) {
                                fprintf(stderr, "Ошибка дешифрования AES ключа.\n");
                                free(data);
                                return -1;
                            }

                            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                            int len, plaintext_len;
                            unsigned char *plaintext = malloc(ct_len + 1);
                            if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
                                fprintf(stderr, "Ошибка инициализации дешифрования файла.\n");
                                free(data);
                                free(plaintext);
                                return -1;
                            }
                            if (!EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv)) {
                                fprintf(stderr, "Ошибка установки ключа/IV для файла.\n");
                                free(data);
                                free(plaintext);
                                return -1;
                            }
                            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAGLEN, tag);
                            if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len)) {
                                fprintf(stderr, "Ошибка дешифрования файла.\n");
                                free(data);
                                free(plaintext);
                                return -1;
                            }
                            plaintext_len = len;
                            if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
                                fprintf(stderr, "Ошибка завершения дешифрования файла.\n");
                                EVP_CIPHER_CTX_free(ctx);
                                free(data);
                                free(plaintext);
                                return -1;
                            }
                            plaintext_len += len;
                            plaintext[plaintext_len] = '\0';
                            EVP_CIPHER_CTX_free(ctx);
                            free(data);

                            // Записываем расшифрованный файл (удаляем расширение .enc)
                            strncpy(decrypted_file_path, encrypted_file_path, path_size);
                            char *dot = strrchr(decrypted_file_path, '.');
                            if (dot) *dot = '\0';
                            FILE *fp = fopen(decrypted_file_path, "wb");
                            if (!fp) {
                                fprintf(stderr, "Не удалось создать расшифрованный файл.\n");
                                free(plaintext);
                                return -1;
                            }
                            fwrite(plaintext, 1, plaintext_len, fp);
                            fclose(fp);
                            free(plaintext);
                            return 0;
                        }

                        /* ============================================================================
                         *   Простейшее меню и основной цикл программы.
                         * ============================================================================ */
                        void print_menu() {
                            printf("\n--- Главное меню ---\n");
                            printf("1. Создать пару ключей \n");
                            printf("2. Зашифровать текст AES-GCM\n");
                            printf("3. Расшифровать текст AES-GCM\n");
                            printf("4. Зашифровать файл AES-GCM \n");
                            printf("5. Расшифровать файл AES-GCM \n");
                            printf("0. Выйти из программы\n");
                        }

                        int main() {
                            OpenSSL_add_all_algorithms();
                            ERR_load_crypto_strings();

                            const char *json_file = "keys.json";
                            char choice[10];
                            while (1) {
                                print_menu();
                                printf("Выберите действие: ");
                                fgets(choice, sizeof(choice), stdin);
                                int option = atoi(choice);
                                if (option == 0) {
                                    printf("Выход из программы.\n");
                                    break;
                                }
                                if (option == 1) {
                                    char username[100];
                                    printf("Введите имя пользователя: ");
                                    fgets(username, sizeof(username), stdin);
                                    username[strcspn(username, "\n")] = '\0';
                                    char *priv_filename = NULL, *pub_filename = NULL;
                                    if (generate_key_pair(username, &priv_filename, &pub_filename) == 0) {
                                        save_keys_to_json(username, pub_filename, priv_filename, json_file);
                                    }
                                    free(priv_filename);
                                    free(pub_filename);
                                }
                                else if (option == 2) {
                                    char *plaintext = get_multiline_input();
                                    char pub_key_path[512];
                                    printf("Введите путь к публичному ключу: ");
                                    fgets(pub_key_path, sizeof(pub_key_path), stdin);
                                    pub_key_path[strcspn(pub_key_path, "\n")] = '\0';
                                    cJSON *json = encrypt_text_gcm(pub_key_path, plaintext);
                                    if (json) {
                                        char *rendered = cJSON_Print(json);
                                        printf("Зашифрованные данные (JSON с base64):\n%s\n", rendered);
                                        free(rendered);
                                        cJSON_Delete(json);
                                    }
                                    free(plaintext);
                                }
                                else if (option == 3) {
                                    char priv_key_path[512];
                                    printf("Введите путь к приватному ключу: ");
                                    fgets(priv_key_path, sizeof(priv_key_path), stdin);
                                    priv_key_path[strcspn(priv_key_path, "\n")] = '\0';
                                    printf("Введите зашифрованные данные (JSON). Для многострочного ввода введите 'EOF' на отдельной строке:\n");
                                    char *json_input = get_multiline_input();
                                    cJSON *json = cJSON_Parse(json_input);
                                    free(json_input);
                                    if (json) {
                                        char *plaintext = decrypt_text_gcm(priv_key_path, json);
                                        if (plaintext) {
                                            printf("Расшифрованный текст:\n%s\n", plaintext);
                                            free(plaintext);
                                        }
                                        cJSON_Delete(json);
                                    } else {
                                        printf("Ошибка парсинга JSON.\n");
                                    }
                                }
                                else if (option == 4) {
                                    char pub_key_path[512], file_path[512], encrypted_file_path[512];
                                    printf("Введите путь к публичному ключу: ");
                                    fgets(pub_key_path, sizeof(pub_key_path), stdin);
                                    pub_key_path[strcspn(pub_key_path, "\n")] = '\0';
                                    printf("Введите путь к файлу для шифрования: ");
                                    fgets(file_path, sizeof(file_path), stdin);
                                    file_path[strcspn(file_path, "\n")] = '\0';
                                    if (encrypt_file_gcm(pub_key_path, file_path, encrypted_file_path, sizeof(encrypted_file_path)) == 0) {
                                        printf("Файл зашифрован и сохранен как: %s\n", encrypted_file_path);
                                    }
                                }
                                else if (option == 5) {
                                    char priv_key_path[512], enc_file_path[512], dec_file_path[512];
                                    printf("Введите путь к приватному ключу: ");
                                    fgets(priv_key_path, sizeof(priv_key_path), stdin);
                                    priv_key_path[strcspn(priv_key_path, "\n")] = '\0';
                                    printf("Введите путь к зашифрованному файлу: ");
                                    fgets(enc_file_path, sizeof(enc_file_path), stdin);
                                    enc_file_path[strcspn(enc_file_path, "\n")] = '\0';
                                    if (decrypt_file_gcm(priv_key_path, enc_file_path, dec_file_path, sizeof(dec_file_path)) == 0) {
                                        printf("Файл расшифрован и сохранен как: %s\n", dec_file_path);
                                    }
                                }
                                else {
                                    printf("Неверный выбор.\n");
                                }
                            }
                            EVP_cleanup();
                            ERR_free_strings();
                            return 0;
                        }
