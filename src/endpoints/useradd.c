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

#include <cecies/encrypt.h>
#include <cecies/decrypt.h>
#include <mbedtls/platform_util.h>

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/constants.h"
#include "opsick/endpoints/useradd.h"

static uint8_t api_key_public[32];

void opsick_init_endpoint_useradd()
{
    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);
    memcpy(api_key_public, adminsettings.api_key_public, sizeof(api_key_public));
}

void opsick_post_useradd(http_s* request)
{
    if (!opsick_verify(request, api_key_public))
    {
        http_send_error(request, 403);
        return;
    }

    char* json = NULL;
    size_t json_length = 0;

    FIOBJ jsonobj = FIOBJ_INVALID;
    FIOBJ pw_jsonkey = fiobj_str_new("pw", 2);
    FIOBJ exp_utc_jsonkey = fiobj_str_new("exp_utc", 7);
    FIOBJ body_jsonkey = fiobj_str_new("body", 4);
    FIOBJ public_key_ed25519_jsonkey = fiobj_str_new("public_key_ed25519", 18);
    FIOBJ encrypted_private_key_ed25519_jsonkey = fiobj_str_new("encrypted_private_key_ed25519", 29);
    FIOBJ public_key_curve448_jsonkey = fiobj_str_new("public_key_curve448", 19);
    FIOBJ encrypted_private_key_curve448_jsonkey = fiobj_str_new("encrypted_private_key_curve448", 30);

    if (opsick_decrypt(request, &json) != 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    json_length = strlen(json);
    if (json_length == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    if (fiobj_json2obj(&jsonobj, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const FIOBJ pw_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ exp_utc_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ body_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ public_key_ed25519_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ encrypted_private_key_ed25519_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ public_key_curve448_obj = fiobj_hash_get(jsonobj, pw_jsonkey);
    const FIOBJ encrypted_private_key_curve448_obj = fiobj_hash_get(jsonobj, pw_jsonkey);

    if (!pw_obj || !exp_utc_obj || !body_obj || !public_key_ed25519_obj || !public_key_curve448_obj || !encrypted_private_key_ed25519_obj || !encrypted_private_key_curve448_obj)
    {
        http_send_error(request, 403);
        goto exit;
    }

    const int r = opsick_db_create_user(fiobj_obj2cstr(pw_obj).data, (time_t)fiobj_obj2num(exp_utc_obj), fiobj_obj2cstr(body_obj).data, fiobj_obj2cstr(public_key_ed25519_obj).data, fiobj_obj2cstr(encrypted_private_key_ed25519_obj).data, fiobj_obj2cstr(public_key_curve448_obj).data, fiobj_obj2cstr(encrypted_private_key_curve448_obj).data);
    if (r != 0)
    {
        fprintf(stderr, "Failure to create new user server-side using \"opsick_db_create_user()\". Returned error code: %d", r);
        http_send_error(request, 403);
        goto exit;
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

    if (!fiobj_type_is(jsonobj, FIOBJ_INVALID))
    {
        fiobj_free(jsonobj);
    }

    fiobj_free(pw_jsonkey);
    fiobj_free(exp_utc_jsonkey);
    fiobj_free(body_jsonkey);
    fiobj_free(public_key_ed25519_jsonkey);
    fiobj_free(encrypted_private_key_ed25519_jsonkey);
    fiobj_free(public_key_curve448_jsonkey);
    fiobj_free(encrypted_private_key_curve448_jsonkey);
}

void opsick_free_endpoint_useradd()
{
    mbedtls_platform_zeroize(api_key_public, sizeof(api_key_public));
}