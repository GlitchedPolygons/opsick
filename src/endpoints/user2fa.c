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
    // TODO: check if user action is validate, enable or disable.
    //  - When disabling, check TOTP first.
    //  - When enabling, check if it's not active yet (return status code 400 if the user is trying to enable an already 2FA-enabled account).


    // TODO: activate or deactivate the user's 2FA (depending on the passed request body).

}

void opsick_free_endpoint_user2fa()
{
    mbedtls_platform_zeroize(api_key_public, sizeof(api_key_public));
}