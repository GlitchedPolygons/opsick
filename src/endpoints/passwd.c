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
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/endpoints/pubkey.h"

void opsick_init_endpoint_passwd()
{
    // nop
}

void opsick_post_passwd(http_s* request)
{
    // TODO: decrypt request, check pw, eventually check TOTP, perform action
}

void opsick_free_endpoint_passwd()
{
    // nop
}