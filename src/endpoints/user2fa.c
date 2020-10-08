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
#include "opsick/endpoints/user2fa.h"

static uint8_t api_key_public[32];

void opsick_init_endpoint_user2fa()
{
    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);
    memcpy(api_key_public, adminsettings.api_key_public, sizeof(api_key_public));
}

void opsick_post_user2fa(http_s* request)
{
    if (!opsick_verify_request_signature(request, api_key_public))
    {
        http_send_error(request, 403);
        return;
    }

    char* json = NULL;
    size_t json_length = 0;
    FIOBJ jsonobj = FIOBJ_INVALID;

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

    // TODO: check if user action is validate, enable or disable.
    //  - When disabling, check TOTP first.
    //  - When enabling, check if it's not active yet (return status code 400 if the user is trying to enable an already 2FA-enabled account).

    const FIOBJ userid_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_USER_ID));
    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_PW));
    const FIOBJ totp_obj = fiobj_hash_get(jsonobj, opsick_get_preallocated_string(OPSICK_STRPREALLOC_INDEX_TOTP));

    if (!userid_obj || !fiobj_type_is(userid_obj, FIOBJ_T_NUMBER) || !pw_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const uint64_t userid = (uint64_t)fiobj_obj2num(userid_obj);

    if (opsick_verify_user_pw(userid, fiobj_obj2cstr(pw_obj).data) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    switch (opsick_verify_user_totp(userid, fiobj_obj2cstr(totp_obj).data))
    {
        case 1:
        case 2:
            http_send_error(request, 403);
            goto exit;
    }

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
}

void opsick_free_endpoint_user2fa()
{
    mbedtls_platform_zeroize(api_key_public, sizeof(api_key_public));
}