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

    FIOBJ body = FIOBJ_INVALID;

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

    if (fiobj_json2obj(&body, json, json_length) == 0)
    {
        http_send_error(request, 403);
        goto exit;
    }

    // TODO: impl!

exit:
    if (json != NULL)
    {
        if (json_length > 0)
        {
            mbedtls_platform_zeroize(json, json_length);
        }
        free(json);
    }
    if (!fiobj_type_is(body, FIOBJ_INVALID))
    {
        fiobj_free(body);
    }
}

void opsick_free_endpoint_useradd()
{
    mbedtls_platform_zeroize(api_key_public, sizeof(api_key_public));
}