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
#include <ed25519.h>

#include "opsick/db.h"
#include "opsick/keys.h"
#include "opsick/util.h"
#include "opsick/constants.h"
#include "opsick/endpoints/version.h"

static char json[128];
size_t json_length = 0;

static FIOBJ sigheader;

void opsick_init_endpoint_version()
{
    sigheader = fiobj_str_new(OPSICK_SIGNATURE_RESPONSE_HEADER_NAME, 17);
    snprintf(json, sizeof(json), "{\"serverVersion\":\"%s\",\"serverSchemaVersion\":%lu}", OPSICK_SERVER_VERSION_STR, opsick_db_get_schema_version_number());
    json_length = strlen(json);
}

void opsick_get_version(http_s* request)
{
    struct opsick_ed25519_keypair keypair;
    opsick_keys_get_ed25519_keypair(&keypair);

    uint8_t sig[64];
    ed25519_sign(sig, (unsigned char*)json, json_length, keypair.public_key, keypair.private_key);

    char sighexstr[128 + 1];
    opsick_bin2hexstr(sig, sizeof(sig), sighexstr, sizeof(sighexstr), NULL, 0);

    http_set_header(request, sigheader, fiobj_str_new(sighexstr, 128));
    http_send_body(request, json, json_length);

    mbedtls_platform_zeroize(sig, sizeof(sig));
    mbedtls_platform_zeroize(sighexstr, sizeof(sighexstr));
    mbedtls_platform_zeroize(&keypair, sizeof(keypair));
}

void opsick_free_endpoint_version()
{
    mbedtls_platform_zeroize(json, sizeof(json));
    fiobj_free(sigheader);
}