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

#include "opsick/router.h"
#include "opsick/murmur3.h"
#include "opsick/constants.h"
#include "opsick/endpoints/home.h"
#include "opsick/endpoints/pubkey.h"

static int _opsick_router_initialized = 0;

void opsick_init_router()
{
    if (_opsick_router_initialized)
    {
        return;
    }
    _opsick_router_initialized = 1;
}

void opsick_on_request(http_s* request)
{
    if (!_opsick_router_initialized)
    {
        return;
    }

    const FIOBJ path = request->path;
    if (!fiobj_type_is(path, FIOBJ_T_STRING))
    {
        http_send_error(request, 400);
        return;
    }

    const fio_str_info_s pathstr = fiobj_obj2cstr(path);
    const uint32_t pathstr_hash = murmur3(pathstr.data, (uint32_t)pathstr.len, OPSICK_MURMUR3_SEED);

    switch (pathstr_hash)
    {
        default:
            http_send_error(request, 404);
            break;
        case OPSICK_HOME_PATH_HASH:
            opsick_get_home();
            break;
        case OPSICK_PUBKEY_PATH_HASH:
            opsick_get_pubkey();
            break;
    }
}

void opsick_free_router()
{
    if (!_opsick_router_initialized)
    {
        return;
    }
    _opsick_router_initialized = 0;
}

/*

OPSICK_HTTP_HEADER_X_DATA = fiobj_str_new("X-Data", 6);
OPSICK_HTTP_HEADER_SIGNATURE = fiobj_str_new("Signature", 9);

http_set_header(request, OPSICK_HTTP_HEADER_CONTENT_TYPE, http_mimetype_find("txt", 3));
http_set_header(request, OPSICK_HTTP_HEADER_X_DATA, fiobj_str_new("my data", 7));
http_send_body(request, "Hello World!\r\n", 14);

fiobj_free(OPSICK_HTTP_HEADER_X_DATA);
fiobj_free(OPSICK_HTTP_HEADER_SIGNATURE);

*/