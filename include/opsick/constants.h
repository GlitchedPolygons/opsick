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
 * Opsick current version number.
 */
#define OPSICK_SERVER_VERSION 100

/**
 * Opsick current version number string.
 */
#define OPSICK_SERVER_VERSION_STR "1.0.0"

/**
 * The user config file path (must be a <c>.toml</c> file!).
 */
#define OPSICK_CONFIG_FILE_PATH "config.toml"

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
 * murmur3("/version")
 * </c>
 */
#define OPSICK_VERSION_PATH_HASH 692047655

#pragma endregion

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONSTANTS_H
