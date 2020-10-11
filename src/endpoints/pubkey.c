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

#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/endpoints/pubkey.h"
#include <mbedtls/platform_util.h>

void opsick_init_endpoint_pubkey()
{
    // nop
}

void opsick_get_pubkey(http_s* request)
{
    char json[256];
    size_t json_length;
    opsick_keys_get_public_keys_json(json, &json_length);

    opsick_sign_and_send(request,json,json_length);

    mbedtls_platform_zeroize(json, sizeof(json));
}

void opsick_free_endpoint_pubkey()
{
    // nop
}