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

#include <stdio.h>
#include <http.h>
#include <opsick/constants.h>

// Callback for handling HTTP requests.
void opsick_on_request(http_s* request);

// Read user config, start listening to HTTP requests
// on the user-defined port and start facil.io
int main(void)
{
    // Initialize constants and pre-allocate various values that are used often.
    opsick_init_constants();

    // Listen on port 3000 and any available network binding (NULL == 0.0.0.0).
    http_listen("3000", NULL, .on_request = opsick_on_request, .log = 1);
    fio_start(.threads = 4);

    // Deallocate constants.
    opsick_free_constants();
}

void opsick_on_request(http_s* request)
{
    FIOBJ path = request->path;
    if (!fiobj_type_is(path, FIOBJ_T_STRING))
    {
        http_send_error(request, 400);
        return;
    }

    fio_str_info_s pathstr = fiobj_obj2cstr(path);

    http_set_header(request, HTTP_HEADER_CONTENT_TYPE, http_mimetype_find("txt", 3));
    http_set_header(request, HTTP_HEADER_X_DATA, fiobj_str_new("my data", 7));
    http_send_body(request, "Hello World!\r\n", 14);
}