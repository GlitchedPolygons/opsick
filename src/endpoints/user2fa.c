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

#include <mbedtls/platform_util.h>
#include <tfac.h>
#include <argon2.h>

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/endpoints/user2fa.h"

void opsick_init_endpoint_user2fa()
{
    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);
}

void opsick_post_user2fa(http_s* request)
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
    const FIOBJ action_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_NEW_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!user_id_obj || !pw_obj || !action_obj || !fiobj_type_is(action_obj, FIOBJ_T_NUMBER))
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)strtoull(fiobj_obj2cstr(user_id_obj).data, NULL, 10);
    const struct fio_str_info_s pw_strobj = fiobj_obj2cstr(pw_obj);
    const int action = (int)fiobj_obj2num(action_obj); // 0 == disable; 1 == enable; 2 == verify

    // TODO see todo below
    
    db = opsick_db_connect();
    if (db == NULL)
    {
        http_send_error(request, 500);
        goto exit;
    }

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
    if (opsick_user_has_totp_active(&user_metadata) && !tfac_verify_totp(user_metadata.totps, totp_obj ? fiobj_obj2cstr(totp_obj).data : "", OPSICK_2FA_STEPS, OPSICK_2FA_HASH_ALGO))
    {
        http_send_error(request, 403);
        goto exit;
    }

    // TODO: check if user action is validate, enable or disable.
    //  - When disabling, check TOTP first.
    //  - When enabling, check if it's not active yet (return status code 400 if the user is trying to enable an already 2FA-enabled account).

    // TODO: activate or deactivate the user's 2FA (depending on the passed request body).

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

void opsick_free_endpoint_user2fa()
{
    // nop
}