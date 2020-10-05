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
    if (!opsick_verify(request, api_key_public))
    {
        http_send_error(request, 403);
        return;
    }

    // TODO: impl!
}

void opsick_free_endpoint_userext()
{
    // nop
}