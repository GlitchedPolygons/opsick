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
#include "opsick/constants.h"
#include "opsick/endpoints/version.h"

static char json[128];
size_t json_length = 0;

void opsick_init_endpoint_version()
{
    snprintf(json, sizeof(json), "\n{\"serverVersion\":\"%s\",\"serverSchemaVersion\":%lu}", OPSICK_SERVER_VERSION_STR, opsick_db_get_schema_version_number());
    json_length = strlen(json);
}

void opsick_get_version(http_s* request)
{
    http_send_body(request, json, json_length);
}

void opsick_free_endpoint_version()
{
    mbedtls_platform_zeroize(json, sizeof(json));
}