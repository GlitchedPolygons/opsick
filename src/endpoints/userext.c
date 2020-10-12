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
#include "opsick/endpoints/userext.h"

static uint8_t api_key_public[32];

void opsick_init_endpoint_userext()
{
    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);
    memcpy(api_key_public, adminsettings.api_key_public, sizeof(api_key_public));
}

void opsick_post_userext(http_s* request)
{
    sqlite3* db = NULL;
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
        fprintf(stderr, "API Master tried to extend a user's account by less than the minimum account extension period of 48h...");
        http_send_error(request, 400);
        goto exit;
    }

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

    const time_t ct = time(0);

    if (user_metadata.exp_utc < ct)
    {
        user_metadata.exp_utc = ct;
    }

    user_metadata.exp_utc += ext;

    if (opsick_db_set_user_exp(db, user_id, user_metadata.exp_utc) != 0)
    {
        http_send_error(request, 500);
        goto exit;
    }

    char out_json[128];
    snprintf(out_json, sizeof(out_json), "{\"user_id\":%zu,\"new_exp_utc\":%zu}", user_id, user_metadata.exp_utc);

    opsick_sign_and_send(request, out_json, 0);

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

void opsick_free_endpoint_userext()
{
    // nop
}