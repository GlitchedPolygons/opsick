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

#include <tfac.h>
#include <argon2.h>
#include <mbedtls/platform_util.h>

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/endpoints/passwd.h"

static uint8_t api_key_public[32];
static struct opsick_config_adminsettings adminsettings;

void opsick_init_endpoint_passwd()
{
    opsick_config_get_adminsettings(&adminsettings);
    memcpy(api_key_public, adminsettings.api_key_public, sizeof(api_key_public));
}

void opsick_post_passwd(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    sqlite3* db = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 403);
        goto exit;
    }

    db = opsick_db_connect();
    if (db == NULL)
    {
        http_send_error(request, 500);
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
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj || !new_pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);

    // Fetch user metadata from db.
    if (opsick_db_get_user_metadata(db, user_id, &user_metadata) != 0)
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

    // Check user password.
    if (argon2id_verify(user_metadata.pw, pw_strobj.data, pw_strobj.len) != ARGON2_OK)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // Check TOTP (if user has 2FA enabled).
    if (opsick_user_has_2fa_enabled(&user_metadata) && !tfac_verify_totp(user_metadata.totps, totp_obj ? fiobj_obj2cstr(totp_obj).data : "", OPSICK_2FA_STEPS, OPSICK_2FA_HASH_ALGO))
    {
        http_send_error(request, 403);
        goto exit;
    }

    uint8_t salt[32];
    cecies_dev_urandom(salt, sizeof(salt));

    char new_pw_hash[256] = { 0x00 };
    const struct fio_str_info_s new_pw_strobj = fiobj_obj2cstr(new_pw_obj);

    int r = argon2id_hash_encoded(adminsettings.argon2_time_cost, adminsettings.argon2_memory_cost, adminsettings.argon2_parallelism, new_pw_strobj.data, new_pw_strobj.len, salt, sizeof(salt), 64, new_pw_hash, sizeof(new_pw_hash) - 1);
    if (r != ARGON2_OK)
    {
        fprintf(stderr, "Failure to hash user's password server-side using \"argon2id_hash_encoded()\". Returned error code: %d", r);
        http_send_error(request, 500);
        goto exit;
    }

    if (opsick_db_set_user_pw(db, user_id, new_pw_hash) != 0)
    {
        fprintf(stderr, "Failure to write new user pw hash to db.");
        http_send_error(request, 500);
        goto exit;
    }

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
    opsick_db_disconnect(db);
    mbedtls_platform_zeroize(&user_metadata, sizeof(user_metadata));
}

void opsick_free_endpoint_passwd()
{
    mbedtls_platform_zeroize(&adminsettings, sizeof(adminsettings));
    mbedtls_platform_zeroize(api_key_public, sizeof(api_key_public));
}