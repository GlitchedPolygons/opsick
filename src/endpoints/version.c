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

#include "opsick/db.h"
#include "opsick/constants.h"
#include "opsick/endpoints/version.h"

static FIOBJ server_v_header;
static FIOBJ server_schema_v_header;

static FIOBJ server_v;
static FIOBJ server_schema_v;

void opsick_init_endpoint_version()
{
    server_v_header = fiobj_str_new("server-version", 14);
    server_schema_v_header = fiobj_str_new("server-schema-version", 21);

    char schema[32];
    snprintf(schema, sizeof(schema), "%lu", opsick_db_get_schema_version_number());

    server_v = fiobj_str_new(OPSICK_SERVER_VERSION_STR, strlen(OPSICK_SERVER_VERSION_STR));
    server_schema_v = fiobj_str_new(schema, strlen(schema));
}

void opsick_get_version(http_s* request)
{
    http_set_header(request, server_v_header, fiobj_str_copy(server_v));
    http_set_header(request, server_schema_v_header, fiobj_str_copy(server_schema_v));

    http_finish(request);
}

void opsick_free_endpoint_version()
{
    fiobj_free(server_v_header);
    fiobj_free(server_schema_v_header);

    fiobj_free(server_v);
    fiobj_free(server_schema_v);
}