/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef OPSICK_CONSTANTS_H
#define OPSICK_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file constants.h
 * @author Raphael Beck
 * @brief Opsick constants (pre-processor #defines).
 */

/**
 * @mainpage Opsick
 * @section intro Introduction
 * Welcome to the API Documentation for Opsick. <br>
 * Opsick is an open-source password manager written entirely in C.
 * @section install Dependencies, installation and all that...
 * See the git repository's [README.md](https://github.com/GlitchedPolygons/opsick) for more instructions. <br>
 * https://glitchedpolygons.github.io/opsick/files.html
 */

/**
 * Opsick current version number.
 */
#define OPSICK_SERVER_VERSION 100

/**
 * Opsick current version number string.
 */
#define OPSICK_SERVER_VERSION_STR "1.0.0"

/**
 * The maximum length of the instance's user creation endpoint password hash.
 */
#define OPSICK_MAX_USER_CREATION_PASSWORD_LENGTH 256

/**
 * Maximum amount of threads to allow for usage by Argon2.
 */
#define OPSICK_MAX_ARGON2_PARALLELISM 16

/**
 * Standard 2FA token stepcount of 30 seconds.
 */
#define OPSICK_2FA_STEPS 30

/**
 * Standard 2FA token digit count of 6 digits.
 */
#define OPSICK_2FA_DIGITS 6

/**
 * Standard 2FA token HMAC hash algo SHA-1.
 */
#define OPSICK_2FA_HASH_ALGO 0

#pragma region DEFAULT CONFIG VALUES

/**
 * Boolean setting that determines whether or not Opsick should log all HTTP-requests by default. <p>
 * \c 0 means \c false and any non-zero value means \c true
 */
#define OPSICK_DEFAULT_LOG 0

/**
 * Default port to which Opsick should listen to.
 */
#define OPSICK_DEFAULT_PORT 6677

/**
 * Default amount of threads that the Opsick instance should use to serve its endpoints.
 */
#define OPSICK_DEFAULT_THREADS 2

/**
 * Default max client count limit. \c 0 means unlimited.
 */
#define OPSICK_DEFAULT_MAX_CLIENTS 0

/**
 * Default header size limit in bytes for all endpoints.
 */
#define OPSICK_DEFAULT_MAX_HEADER_SIZE (1024 * 16)

/**
 * Default body size limit in bytes for all endpoints.
 */
#define OPSICK_DEFAULT_MAX_BODY_SIZE (1024 * 1024 * 16)

/**
 * Default maximum users limit for the Opsick instance (\c 0 means unlimited users).
 */
#define OPSICK_DEFAULT_MAX_USERS 0

/**
 * Default API key algo ( currently \c 0 which is \c ed25519 ).
 */
#define OPSICK_DEFAULT_API_KEY_ALGO 0

/**
 * Boolean setting for whether or not Opsick should serve the \c index.html file by default.
 */
#define OPSICK_DEFAULT_USE_INDEX_HTML 1

/**
 * Default Argon2 time cost parameter (iterations).
 */
#define OPSICK_DEFAULT_ARGON2_TIME_COST 16

/**
 * Default Argon2 memory cost parameter (in KiB).
 */
#define OPSICK_DEFAULT_ARGON2_MEMORY_COST_KiB (1024 * 64)

/**
 * Default Argon2 parallelism setting.
 */
#define OPSICK_DEFAULT_ARGON2_PARALLELISM 2

/**
 * Default key regeneration interval in hours.
 */
#define OPSICK_DEFAULT_KEY_REFRESH_INTERVAL_HOURS 72

/**
 * Default API Key (public ed25519 key as hex-encoded string).
 */
#define OPSICK_DEFAULT_API_KEY_PUBLIC_HEXSTR "F407F5E089CE64002EB417FB683A7302287BE84108BB8E62FD8ED647DC62805C"

/**
 * Default user registration password is \c "opsick_registration_password".
 */
#define OPSICK_DEFAULT_USER_CREATION_PASSWORD_ARGON2_HASH "$argon2id$v=19$m=65536,t=16,p=2$kgiReuAb6UDkBgssL08W9OoHkkDzNV++5cWzHB5fUbE$JG8ODw0sHhBuROEF3iA8w9RbrUF59UGnOz3bmkY4SAy0MzJ6tL+HG9j2ipxcvHnpZC1H6HeHJqaAb1Yqplevcw"

#pragma endregion

#if defined(_WIN32)
#define OPSICK_DEFAULT_DBCONN_FILE "C:\\opsick\\dbconn"
#elif defined(__APPLE__)
#define OPSICK_DEFAULT_DBCONN_FILE "/usr/local/share/opsick/dbconn"
#else
#define OPSICK_DEFAULT_DBCONN_FILE "/var/opt/opsick/dbconn"
#endif

#pragma region STRING PRE - ALLOCATION IDs

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "ed25519-signature".
 */
#define OPSICK_STRPREALLOC_INDEX_ED25519_SIG 0

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "user_id".
 */
#define OPSICK_STRPREALLOC_INDEX_USER_ID 1

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "pw".
 */
#define OPSICK_STRPREALLOC_INDEX_PW 2

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "totp".
 */
#define OPSICK_STRPREALLOC_INDEX_TOTP 3

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "new_pw".
 */
#define OPSICK_STRPREALLOC_INDEX_NEW_PW 4

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "exp_utc".
 */
#define OPSICK_STRPREALLOC_INDEX_EXP_UTC 5

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "body".
 */
#define OPSICK_STRPREALLOC_INDEX_BODY 6

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "public_key_ed25519".
 */
#define OPSICK_STRPREALLOC_INDEX_PUBKEY_ED25519 7

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "encrypted_private_key_ed25519".
 */
#define OPSICK_STRPREALLOC_INDEX_PRVKEY_ED25519 8

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "public_key_curve448".
 */
#define OPSICK_STRPREALLOC_INDEX_PUBKEY_CURVE448 9

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "encrypted_private_key_curve448".
 */
#define OPSICK_STRPREALLOC_INDEX_PRVKEY_CURVE448 10

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "ext".
 */
#define OPSICK_STRPREALLOC_INDEX_EXT 11

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "body_sha512".
 */
#define OPSICK_STRPREALLOC_INDEX_BODY_SHA512 12

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "action".
 */
#define OPSICK_STRPREALLOC_INDEX_ACTION 13

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "ucpw".
 */
#define OPSICK_STRPREALLOC_INDEX_USER_CREATION_PW 14

/**
 * Index to pass to #opsick_get_preallocated_string() to receive back the FIOBJ string "www-authenticate".
 */
#define OPSICK_STRPREALLOC_INDEX_WWW_AUTHENTICATE_HEADER 15

#pragma endregion

#pragma region HASHES

/**
 * The seed value to use for the MurmurHash v3 algo.
 * Since all of the hash lookups are only correlated
 * to endpoint routing, this value needn't be secret.
 */
#define OPSICK_MURMUR3_SEED 133769420

/**
 * <c>
 * murmur3("/")
 * </c>
 */
#define OPSICK_HOME_PATH_HASH 2818192833

/**
 * <c>
 * murmur3("/favicon.ico")
 * </c>
 */
#define OPSICK_FAVICON_PATH_HASH 1051445893

/**
 * <c>
 * murmur3("/pubkey")
 * </c>
 */
#define OPSICK_PUBKEY_PATH_HASH 3855421118

/**
 * <c>
 * murmur3("/users/prvkey")
 * </c>
 */
#define OPSICK_PRVKEY_PATH_HASH 944329335

/**
 * <c>
 * murmur3("/users/passwd")
 * </c>
 */
#define OPSICK_PASSWD_PATH_HASH 2697305887

/**
 * <c>
 * murmur3("/users")
 * </c>
 */
#define OPSICK_USERGET_PATH_HASH 456400922

/**
 * <c>
 * murmur3("/users/check")
 * </c>
 */
#define OPSICK_USERCHK_PATH_HASH 4075223429

/**
 * <c>
 * murmur3("/users/create")
 * </c>
 */
#define OPSICK_USERADD_PATH_HASH 4242582731

/**
 * <c>
 * murmur3("/users/delete")
 * </c>
 */
#define OPSICK_USERDEL_PATH_HASH 1184612068

/**
 * <c>
 * murmur3("/users/extend")
 * </c>
 */
#define OPSICK_USEREXT_PATH_HASH 628309221

/**
 * <c>
 * murmur3("/users/body")
 * </c>
 */
#define OPSICK_USERBODY_PATH_HASH 413204006

/**
 * <c>
 * murmur3("/users/2fa")
 * </c>
 */
#define OPSICK_USER2FA_PATH_HASH 2196777087

/**
 * <c>
 * murmur3("/users/keys")
 * </c>
 */
#define OPSICK_USERKEYS_PATH_HASH 773720762

/**
 * <c>
 * murmur3("/users/keys/update")
 * </c>
 */
#define OPSICK_USERKEYS_UPDATE_PATH_HASH 589266831

/**
 * <c>
 * murmur3("/version")
 * </c>
 */
#define OPSICK_VERSION_PATH_HASH 692047655

#pragma endregion

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONSTANTS_H
