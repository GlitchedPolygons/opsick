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

#include <fiobject.h>
#include <cecies/encrypt.h>
#include <cecies/decrypt.h>
#include <mbedtls/platform_util.h>

#include "argon2.h"
#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/constants.h"
#include "opsick/endpoints/useradd.h"

static struct opsick_config_adminsettings adminsettings;

void opsick_init_endpoint_useradd()
{
    opsick_config_get_adminsettings(&adminsettings);
}

void opsick_post_useradd(http_s* request)
{
    sqlite3* db = NULL;
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
    const FIOBJ exp_utc_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_EXP_UTC));
    const FIOBJ body_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_BODY));
    const FIOBJ public_key_ed25519_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_ED25519));
    const FIOBJ encrypted_private_key_ed25519_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_ED25519));
    const FIOBJ public_key_curve448_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PUBKEY_CURVE448));
    const FIOBJ encrypted_private_key_curve448_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PRVKEY_CURVE448));

    if (!pw_obj || !exp_utc_obj || !public_key_ed25519_obj || !public_key_curve448_obj || !encrypted_private_key_ed25519_obj || !encrypted_private_key_curve448_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const fio_str_info_s pw = fiobj_obj2cstr(pw_obj);
    const fio_str_info_s userpubkey_ed25519 = fiobj_obj2cstr(public_key_ed25519_obj);
    const fio_str_info_s userpubkey_curve448 = fiobj_obj2cstr(public_key_curve448_obj);

    if (userpubkey_ed25519.len != 64 || userpubkey_curve448.len != 112)
    {
        fprintf(stderr, "Invalid public key length");
        http_send_error(request, 403);
        goto exit;
    }

    uint8_t salt[32];
    cecies_dev_urandom(salt, 32);

    char pw_hash[256];
    mbedtls_platform_zeroize(pw_hash, sizeof(pw_hash));

    int r = argon2id_hash_encoded(adminsettings.argon2_time_cost, adminsettings.argon2_memory_cost, adminsettings.argon2_parallelism, pw.data, pw.len, salt, sizeof(salt), 64, pw_hash, sizeof(pw_hash) - 1);
    if (r != ARGON2_OK)
    {
        fprintf(stderr, "Failure to hash user's password server-side using \"argon2id_hash_encoded()\". Returned error code: %d", r);
        http_send_error(request, 403);
        goto exit;
    }

    db = opsick_db_connect();
    if (db == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

    uint64_t user_id = 0;
    r = opsick_db_create_user(db, pw_hash, (uint64_t)strtoull(fiobj_obj2cstr(exp_utc_obj).data, NULL, 10), fiobj_obj2cstr(body_obj).data, userpubkey_ed25519.data, fiobj_obj2cstr(encrypted_private_key_ed25519_obj).data, userpubkey_curve448.data, fiobj_obj2cstr(encrypted_private_key_curve448_obj).data, &user_id);
    if (r != 0)
    {
        fprintf(stderr, "Failure to create new user server-side using \"opsick_db_create_user()\". Returned error code: %d", r);
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
    opsick_db_disconnect(db);
}

void opsick_free_endpoint_useradd()
{
    mbedtls_platform_zeroize(&adminsettings, sizeof(adminsettings));
}