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

#include "opsick/endpoints/home.h"

static char html[8192];
static size_t html_len;

void opsick_init_endpoint_home()
{
    memset(html, '\0', sizeof(html));

    FILE* fptr = fopen("index.html", "r");
    if (fptr == NULL)
    {
        perror("ERROR: Couldn't open index.html file! ");
        // Program should exit if file pointer returned by fopen() is NULL.
        exit(1);
    }

    fseek(fptr, 0L, SEEK_END);
    const long fsize = ftell(fptr);

    fseek(fptr, 0L, SEEK_SET);
    html_len = fread(html, 1, fsize, fptr);

    html[html_len++] = '\0';
    fclose(fptr);
}

void opsick_get_home(http_s* request)
{
    // TODO: sign response body (set signature header)
    http_send_body(request, html, html_len);
}

void opsick_free_endpoint_home()
{
    html_len = 0;
    memset(html, '\0', sizeof(html));
}