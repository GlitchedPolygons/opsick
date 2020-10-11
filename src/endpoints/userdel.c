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

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/endpoints/userdel.h"

void opsick_init_endpoint_userdel()
{
    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);
}

void opsick_post_userdel(http_s* request)
{
    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;
    sqlite3* db = NULL;
    struct opsick_user_metadata user_metadata = { 0x00 };

    if (!opsick_request_has_signature(request))
    {
        http_send_error(request, 500);
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

    const FIOBJ userid_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!userid_obj || !fiobj_type_is(userid_obj, FIOBJ_T_NUMBER) || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t user_id = (uint64_t)fiobj_obj2num(userid_obj);

    switch (opsick_verify_user_pw_and_totp(user_id, fiobj_obj2cstr(pw_obj).data, fiobj_obj2cstr(totp_obj).data))
    {
        case 1:
        case 2:
            http_send_error(request, 403);
            goto exit;
    }

    if (opsick_db_delete_user(db, user_id) != 0)
    {
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
}

void opsick_free_endpoint_userdel()
{
    // nop
}