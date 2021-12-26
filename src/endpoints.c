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

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/endpoints.h"

#include <tfac.h>
#include <argon2.h>
#include <stddef.h>
#include <cecies/encrypt.h>
#include <mbedtls/platform_util.h>

static uint8_t initialized = 0;

static char* html = NULL;
static size_t html_len = 0;

static char version_json[128] = { 0 };
static size_t version_json_length = 0;

static struct opsick_config_adminsettings adminsettings;

// Initialization and destruction:

void opsick_endpoints_init()
{
    if (initialized)
    {
        return;
    }
    initialized = 1;

    opsick_config_get_adminsettings(&adminsettings);

    if (adminsettings.use_index_html)
    {
        FILE* fptr = fopen("index.html", "r");
        if (fptr == NULL)
        {
            perror("ERROR: Couldn't open index.html file! ");
            // Program should exit if file pointer returned by fopen() is NULL.
            exit(1);
        }

        fseek(fptr, 0L, SEEK_END);
        const long fsize = ftell(fptr);

        html = malloc(fsize + 1);
        if (html == NULL)
        {
            perror("ERROR: Memory allocation failed when attempting to read index.html into memory... Out of memory?");
            exit(2);
        }

        fseek(fptr, 0L, SEEK_SET);
        html_len = fread(html, 1, fsize, fptr);

        html[html_len++] = '\0';
        fclose(fptr);
    }

    snprintf(version_json, sizeof(version_json), "{\"server_name\":\"opsick\",\"server_version\":\"%s\",\"server_schema_version\":%zu}", OPSICK_SERVER_VERSION_STR, opsick_db_get_schema_version_number());
    version_json_length = strlen(version_json);
}

void opsick_endpoints_free()
{
    if (!initialized)
    {
        return;
    }
    initialized = 0;

    free(html);
    html = NULL;
    html_len = 0;
    mbedtls_platform_zeroize(&version_json, sizeof(version_json));
    mbedtls_platform_zeroize(&adminsettings, sizeof(adminsettings));
}

// Often used functions that can be inlined:

static inline int valid_totp(struct opsick_user_metadata* user_metadata, const FIOBJ totp_obj)
{
    return !opsick_user_has_2fa_enabled(user_metadata) || tfac_verify_totp(user_metadata->totps, totp_obj ? fiobj_obj2cstr(totp_obj).data : "", OPSICK_2FA_DIGITS, OPSICK_2FA_STEPS, OPSICK_2FA_HASH_ALGO);
}

static inline int valid_pw(struct opsick_user_metadata* user_metadata, const FIOBJ pw_obj)
{
    const fio_str_info_s pw = fiobj_obj2cstr(pw_obj);
    return argon2id_verify(user_metadata->pw, pw.data, pw.len) == ARGON2_OK;
}

static inline int is_user_registration_pw_enabled()
{
    for (size_t i = 0; i < sizeof(adminsettings.user_registration_password); ++i)
    {
        if (adminsettings.user_registration_password[i] != 0x00)
            return 1;
    }
    return 0;
}

// Endpoints:

void opsick_get_home(http_s* request)
{
    if (html == NULL || html_len == 0)
    {
        http_finish(request);
        return;
    }

    opsick_sign_and_send(request, html, html_len);
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_get_pubkey(http_s* request)
{
    char json[256];
    size_t json_length;
    opsick_keys_get_public_keys_json(json, &json_length);

    opsick_sign_and_send(request, json, json_length);

    mbedtls_platform_zeroize(json, sizeof(json));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_does_id_exist(http_s* request)
{
    PGconn* dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    const struct fio_str_info_s body = fiobj_obj2cstr(request->body);
    if (body.data == NULL || body.len == 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    const uint64_t user_id = strtoull(body.data, NULL, 10);
    if (opsick_db_does_user_id_exist(dbconn, user_id))
    {
        http_finish(request);
    }
    else
    {
        http_send_error(request, 404);
    }

exit:
    opsick_db_disconnect(dbconn);
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_create(http_s* request)
{
    PGconn* dbconn = NULL;
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (!opsick_verify_api_request_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ ucpw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_CREATION_PW));
    const FIOBJ exp_utc_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_EXP_UTC));
    const FIOBJ public_key_ed25519_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_ED25519));
    const FIOBJ encrypted_private_key_ed25519_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_ED25519));
    const FIOBJ public_key_curve448_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_CURVE448));
    const FIOBJ encrypted_private_key_curve448_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_CURVE448));

    if (!pw_obj || !exp_utc_obj || !public_key_ed25519_obj || !public_key_curve448_obj || !encrypted_private_key_ed25519_obj || !encrypted_private_key_curve448_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (is_user_registration_pw_enabled())
    {
        if (!ucpw_obj)
        {
            http_send_error(request, 403);
            goto exit;
        }

        const struct fio_str_info_s ucpw = fiobj_obj2cstr(ucpw_obj);

        int rot = argon2id_verify(adminsettings.user_registration_password, ucpw.data, ucpw.len);
        if (rot != ARGON2_OK)
        {
            http_send_error(request, 403);
            goto exit;
        }
    }

    const fio_str_info_s pw = fiobj_obj2cstr(pw_obj);
    const fio_str_info_s userpubkey_ed25519 = fiobj_obj2cstr(public_key_ed25519_obj);
    const fio_str_info_s userpubkey_curve448 = fiobj_obj2cstr(public_key_curve448_obj);

    if (userpubkey_ed25519.len != 64 || userpubkey_curve448.len != 112)
    {
        fprintf(stderr, "ERROR: Invalid public key length. \n");
        http_send_error(request, 403);
        goto exit;
    }

    uint8_t salt[32];
    cecies_dev_urandom(salt, 32);

    char pw_hash[256];
    mbedtls_platform_zeroize(pw_hash, sizeof(pw_hash));

    int r = argon2id_hash_encoded(adminsettings.argon2_time_cost, adminsettings.argon2_memory_cost_kib, adminsettings.argon2_parallelism, pw.data, pw.len, salt, sizeof(salt), 64, pw_hash, sizeof(pw_hash) - 1);
    if (r != ARGON2_OK)
    {
        fprintf(stderr, "ERROR: Failure to hash user's password server-side using \"argon2id_hash_encoded()\". Returned error code: %d \n", r);
        http_send_error(request, 403);
        goto exit;
    }

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    uint64_t user_id = 0;
    r = opsick_db_create_user(dbconn, pw_hash, (uint64_t)strtoull(fiobj_obj2cstr(exp_utc_obj).data, NULL, 10), userpubkey_ed25519.data, fiobj_obj2cstr(encrypted_private_key_ed25519_obj).data, userpubkey_curve448.data, fiobj_obj2cstr(encrypted_private_key_curve448_obj).data, &user_id);
    if (r != 0)
    {
        fprintf(stderr, "ERROR: Failure to create new user server-side using \"opsick_db_create_user()\". Returned error code: %d \n", r);
        http_send_error(request, 403);
        goto exit;
    }

    char out_json[64];
    snprintf(out_json, sizeof(out_json), "{\"user_id\":%zu}", user_id);

    opsick_sign_and_send(request, out_json, strlen(out_json));

    mbedtls_platform_zeroize(out_json, sizeof(out_json));
    mbedtls_platform_zeroize(&user_id, sizeof(user_id));
    mbedtls_platform_zeroize(pw_hash, sizeof(pw_hash));
    mbedtls_platform_zeroize(salt, sizeof(salt));

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_body(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));
    const FIOBJ body_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_BODY));

    if (!user_id_obj || !pw_obj || !body_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    // Fetch user metadata from db.
    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Verify request signature.
    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Check if user is expired.
    if ((uint64_t)time(0) > user_metadata.exp_utc)
    {
        http_send_error(request, 418);
        goto exit;
    }

    // Check user password.
    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Check TOTP (if user has 2FA enabled).
    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Write new body into db.
    if (opsick_db_set_user_body(dbconn, user_id, fiobj_obj2cstr(body_obj).data) != 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    char sig[128 + 1];
    opsick_sign(pw_strobj.data, pw_strobj.len, sig);

    http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
    http_finish(request);

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_passwd(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ new_pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_NEW_PW));
    const FIOBJ new_enc_ed25519_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_ED25519));
    const FIOBJ new_enc_curve448_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_CURVE448));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj || !new_pw_obj || !new_enc_ed25519_key_obj || !new_enc_curve448_key_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    uint8_t salt[32];
    cecies_dev_urandom(salt, sizeof(salt));

    char new_pw_hash[256] = { 0x00 };
    const struct fio_str_info_s new_pw_strobj = fiobj_obj2cstr(new_pw_obj);

    int r = argon2id_hash_encoded(adminsettings.argon2_time_cost, adminsettings.argon2_memory_cost_kib, adminsettings.argon2_parallelism, new_pw_strobj.data, new_pw_strobj.len, salt, sizeof(salt), 64, new_pw_hash, sizeof(new_pw_hash) - 1);
    if (r != ARGON2_OK)
    {
        fprintf(stderr, "ERROR: Failure to hash user's password server-side using \"argon2id_hash_encoded()\". Returned error code: %d \n", r);
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_set_user_pw(dbconn, user_id, new_pw_hash) != 0)
    {
        fprintf(stderr, "ERROR: Failure to write new user pw hash to db. \n");
        http_send_error(request, 500);
        goto exit;
    }

    // Changing the password requires users to re-encrypt their private keys using the new pw.
    if (opsick_db_set_user_keys(dbconn, user_id, user_metadata.public_key_ed25519.hexstring, fiobj_obj2cstr(new_enc_ed25519_key_obj).data, user_metadata.public_key_curve448.hexstring, fiobj_obj2cstr(new_enc_curve448_key_obj).data) != 0)
    {
        fprintf(stderr, "ERROR: Failure to write new user encrypted private keys to db. \n");
        http_send_error(request, 500);
        goto exit;
    }

    char sig[128 + 1];
    opsick_sign(new_pw_strobj.data, new_pw_strobj.len, sig);

    http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
    http_finish(request);

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_2fa(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ action_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ACTION));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj || !action_obj || !fiobj_type_is(action_obj, FIOBJ_T_NUMBER))
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);
    const int action = (int)fiobj_obj2num(action_obj); // 0 == disable; 1 == enable; 2 == verify

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    const int user_has_2fa_enabled = opsick_user_has_2fa_enabled(&user_metadata);
    if (user_has_2fa_enabled && !tfac_verify_totp(user_metadata.totps, totp_obj ? fiobj_obj2cstr(totp_obj).data : "", OPSICK_2FA_DIGITS, OPSICK_2FA_STEPS, OPSICK_2FA_HASH_ALGO))
    {
        http_send_error(request, 403);
        goto exit;
    }

    switch (action)
    {
        case 0: // Disable 2FA (if it's enabled, otherwise just return status code 200).
        {
            if (!user_has_2fa_enabled)
            {
                http_finish(request);
                goto exit;
            }

            if (opsick_db_set_user_totps(dbconn, user_id, NULL) != 0)
            {
                http_send_error(request, 500);
                goto exit;
            }

            char sig[128 + 1];
            opsick_sign(pw_strobj.data, pw_strobj.len, sig);

            http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
            http_finish(request);

            mbedtls_platform_zeroize(sig, sizeof(sig));
            goto exit;
        }
        case 1: // Enable 2FA and return the TOTP secret to the user (or return status 400 if 2FA is already enabled).
        {
            if (user_has_2fa_enabled)
            {
                http_send_error(request, 400);
                goto exit;
            }

            struct tfac_secret totps = tfac_generate_secret();
            opsick_db_set_user_totps(dbconn, user_id, totps.secret_key_base32);

            char out_json[256] = { 0x00 };
            snprintf(out_json, sizeof(out_json), "{\"totps\":\"%s\",\"steps\":%d,\"digits\":%d,\"hash_algo\":\"SHA-1\",\"qr\":\"otpauth://totp/opsick:%zu?secret=%s\"}", totps.secret_key_base32, OPSICK_2FA_STEPS, OPSICK_2FA_DIGITS, user_id, totps.secret_key_base32);

            char* out_enc = NULL;
            size_t out_enc_len = 0;

            if (cecies_curve448_encrypt((uint8_t*)out_json, strlen(out_json), 0, user_metadata.public_key_curve448, (uint8_t**)&out_enc, &out_enc_len, 1) != 0)
            {
                http_send_error(request, 500);

                mbedtls_platform_zeroize(&totps, sizeof(totps));
                mbedtls_platform_zeroize(out_json, sizeof(out_json));
                goto exit;
            }

            opsick_sign_and_send(request, out_enc, out_enc_len);

            free(out_enc);
            mbedtls_platform_zeroize(&totps, sizeof(totps));
            mbedtls_platform_zeroize(out_json, sizeof(out_json));
            goto exit;
        }
        case 2: // If verifying a TOTP was everything the requesting user wanted, leave immediately.
        {
            char sig[128 + 1];
            opsick_sign(pw_strobj.data, pw_strobj.len, sig);

            http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
            http_finish(request);

            mbedtls_platform_zeroize(sig, sizeof(sig));
            goto exit;
        }
        default: // Bad client. Very bad.
        {
            http_send_error(request, 403);
            goto exit;
        }
    }

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_delete(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (opsick_db_delete_user(dbconn, user_id) != 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    char sig[128 + 1];
    opsick_sign(pw_strobj.data, pw_strobj.len, sig);

    http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
    http_finish(request);

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_extend(http_s* request)
{
    PGconn* dbconn = NULL;
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    struct opsick_user_metadata user_metadata = { 0x00 };

    // Don't even bother if the request isn't signed...
    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 500);
        goto exit;
    }

    // Ensure that the request was sent by the API master.
    if (!opsick_verify_api_request_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ ext_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_EXT));

    if (!user_id_obj || !ext_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const uint64_t ext = (uint64_t)strtoull(fiobj_obj2cstr(ext_obj).data, NULL, 10);

    if (ext < 3600 * 48)
    {
        fprintf(stderr, "ERROR: API Master tried to extend a user's account by less than the minimum account extension period of 48h... \n");
        http_send_error(request, 400);
        goto exit;
    }

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const time_t ct = time(0);

    if (user_metadata.exp_utc < ct)
    {
        user_metadata.exp_utc = ct;
    }

    user_metadata.exp_utc += ext;

    if (opsick_db_set_user_exp(dbconn, user_id, user_metadata.exp_utc) != 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    char out_json[128];
    snprintf(out_json, sizeof(out_json), "{\"user_id\":%zu,\"new_exp_utc\":%zu}", user_id, user_metadata.exp_utc);

    opsick_sign_and_send(request, out_json, 0);

    mbedtls_platform_zeroize(out_json, sizeof(out_json));

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_keys(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    char out_json[2048] = { 0x00 };
    snprintf(out_json, sizeof(out_json), "{\"public_key_ed25519\":\"%s\",\"encrypted_private_key_ed25519\":\"%s\",\"public_key_curve448\":\"%s\",\"encrypted_private_key_curve448\":\"%s\"}", user_metadata.public_key_ed25519.hexstring, user_metadata.encrypted_private_key_ed25519, user_metadata.public_key_curve448.hexstring, user_metadata.encrypted_private_key_curve448);

    opsick_sign_and_send(request, out_json, strlen(out_json));

    mbedtls_platform_zeroize(out_json, sizeof(out_json));

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users(http_s* request)
{
    char* body = NULL;
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));
    const FIOBJ body_sha512_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_BODY_SHA512));

    if (!user_id_obj || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // If the last body SHA-512 sent is different from the current one in the db, return the user's newest body too!
    if (opsick_strncmpic(user_metadata.body_sha512, body_sha512_obj ? fiobj_obj2cstr(body_sha512_obj).data : "", 128) != 0)
    {
        size_t bodylen = 0;
        if (opsick_db_get_user_body(dbconn, user_id, &body, &bodylen) != 0)
        {
            http_send_error(request, 403);
            goto exit;
        }

        size_t out_json_length = 1024 + bodylen + 128;
        char* out_json = malloc(out_json_length);

        if (out_json == NULL)
        {
            fprintf(stderr, "OUT OF MEMORY! \n");
            http_send_error(request, 500);
            goto exit;
        }

        snprintf(out_json, out_json_length, //
                "{\"id\":%zu,\"iat_utc\":%zu,\"exp_utc\":%zu,\"lastmod_utc\":%zu,\"body\":\"%s\",\"body_sha512\":\"%s\"}", //
                user_metadata.id, user_metadata.iat_utc, user_metadata.exp_utc, user_metadata.lastmod_utc, body, user_metadata.body_sha512 //
        );

        char* out_enc = NULL;
        size_t out_enc_length = 0;

        if (cecies_curve448_encrypt((uint8_t*)out_json, strlen(out_json), 0, user_metadata.public_key_curve448, (uint8_t**)&out_enc, &out_enc_length, 1) != 0)
        {
            fprintf(stderr, "Curve448 encryption of the HTTP response body failed! \n");
            http_send_error(request, 500);
            free(out_json);
            goto exit;
        }

        opsick_sign_and_send(request, out_enc, out_enc_length);

        mbedtls_platform_zeroize(out_json, out_json_length);
        free(out_json);
        free(out_enc);
    }
    else // User already has the newest body, only return the metadata
    {
        char out_json[256];
        snprintf(out_json, sizeof(out_json),
                "{\"id\":%zu,\"iat_utc\":%zu,\"exp_utc\":%zu,\"lastmod_utc\":%zu}", //
                user_metadata.id, user_metadata.iat_utc, user_metadata.exp_utc, user_metadata.lastmod_utc //
        );

        char* out_enc = NULL;
        size_t out_enc_len = 0;

        if (cecies_curve448_encrypt((uint8_t*)out_json, strlen(out_json), 0, user_metadata.public_key_curve448, (uint8_t**)&out_enc, &out_enc_len, 1) != 0)
        {
            mbedtls_platform_zeroize(out_json, sizeof(out_json));
            http_send_error(request, 500);
            goto exit;
        }

        opsick_sign_and_send(request, out_enc, out_enc_len);

        mbedtls_platform_zeroize(out_json, sizeof(out_json));
        free(out_enc);
    }

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    free(body);
    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_post_users_keys_update(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    PGconn* dbconn = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Decrypt the request body.
    if (opsick_decrypt(request, &json) != 0 || (json_length = strlen(json)) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Parse the decrypted JSON.
    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ user_id_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ new_pub_ed25519_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_ED25519));
    const FIOBJ new_pub_curve448_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_CURVE448));
    const FIOBJ new_enc_prv_ed25519_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_ED25519));
    const FIOBJ new_enc_prv_curve448_key_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_CURVE448));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj || !new_pub_ed25519_key_obj || !new_pub_curve448_key_obj || !new_enc_prv_ed25519_key_obj || !new_enc_prv_curve448_key_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);

    dbconn = opsick_db_connect();
    if (dbconn == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_get_user_metadata(dbconn, user_id, &user_metadata) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!opsick_verify_request_signature(request, user_metadata.public_key_ed25519.hexstring))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_pw(&user_metadata, pw_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (!valid_totp(&user_metadata, totp_obj))
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (opsick_db_set_user_keys(dbconn, user_id, fiobj_obj2cstr(new_pub_ed25519_key_obj).data, fiobj_obj2cstr(new_enc_prv_ed25519_key_obj).data, fiobj_obj2cstr(new_pub_curve448_key_obj).data, fiobj_obj2cstr(new_enc_prv_curve448_key_obj).data) != 0)
    {
        fprintf(stderr, "ERROR: Failure to write new user encrypted private keys to db. \n");
        http_send_error(request, 500);
        goto exit;
    }

    char sig[128 + 1];
    opsick_sign(pw_strobj.data, pw_strobj.len, sig);

    http_set_header(request, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_ED25519_SIG), fiobj_str_new(sig, 128));
    http_finish(request);

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }

    fiobj_free(jsonobj);
    opsick_db_disconnect(dbconn);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

// ---------------------------------------------------------------------------------------------------------------------------------

void opsick_get_version(http_s* request)
{
    opsick_sign_and_send(request, version_json, version_json_length);
}

// ---------------------------------------------------------------------------------------------------------------------------------