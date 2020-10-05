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

#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/endpoints/home.h"

static char* html = NULL;
static size_t html_len = 0;
static uint8_t initialized = 0;

void opsick_init_endpoint_home()
{
    if (initialized)
    {
        return;
    }
    initialized = 1;

    struct opsick_config_adminsettings adminsettings;
    opsick_config_get_adminsettings(&adminsettings);

    if (!adminsettings.use_index_html)
    {
        return;
    }

    FILE* fptr = fopen("index.html", "r");
    if (fptr == NULL)
    {
        perror("ERROR: Couldn't open index.html file! ");
        // Program should exit if file pointer returned by fopen() is NULL.
        exit(1);
    }

    fseek(fptr, 0L, SEEK_END);
    const long fsize = ftell(fptr);

    html = malloc(fsize + 1);
    if (html == NULL)
    {
        perror("ERROR: Memory allocation failed when attempting to read index.html into memory... Out of memory?");
        exit(2);
    }

    fseek(fptr, 0L, SEEK_SET);
    html_len = fread(html, 1, fsize, fptr);

    html[html_len++] = '\0';
    fclose(fptr);
}

void opsick_get_home(http_s* request)
{
    if (html == NULL || html_len == 0)
    {
        http_finish(request);
        return;
    }

    char signature[128 + 1];
    opsick_sign(html, signature);

    http_set_header(request, opsick_get_preallocated_string(OPSICK_PREALLOCATED_STRING_ID_ED25519_SIGNATURE), fiobj_str_new(signature, 128));

    http_send_body(request, html, html_len);
}

void opsick_free_endpoint_home()
{
    if (!initialized)
    {
        return;
    }
    initialized = 0;

    free(html);
    html = NULL;
    html_len = 0;
}