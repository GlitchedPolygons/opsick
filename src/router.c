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

#include "opsick/db.h"
#include "opsick/config.h"
#include "opsick/murmur3.h"
#include "opsick/constants.h"
#include "opsick/endpoints/home.h"
#include "opsick/endpoints/pubkey.h"

static int initialized = 0;

// Read user config, start listening to HTTP requests
// on the user-defined port and start facil.io
void opsick_router_init()
{
    if (initialized)
    {
        return;
    }
    initialized = 1;

    // Initialize endpoints.
    opsick_init_endpoint_home();
    opsick_init_endpoint_pubkey();

    // Start facil.io using the settings provided inside the user config.
    struct opsick_config_hostsettings hostsettings;
    opsick_config_get_hostsettings(&hostsettings);

    char port[64];
    memset(port,'\0', sizeof(port));
    sprintf(port, "%d", hostsettings.port);

    http_listen(
            port,
            NULL,
            .on_request = opsick_on_request,
            .max_header_size = hostsettings.max_header_size,
            .max_body_size = hostsettings.max_body_size,
            .max_clients = hostsettings.max_clients,
            .log = hostsettings.log
    );

    fio_start(.threads = hostsettings.threads);
}

void opsick_on_request(http_s* request)
{
    if (!initialized)
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
        default: {
            http_send_error(request, 404);
            break;
        }
        case OPSICK_FAVICON_PATH_HASH: {
            const int fd = open("favicon.ico", O_RDONLY);
            struct stat st;
            fstat(fd, &st);
            http_sendfile(request, fd, st.st_size, 0);
            close(fd);
            break;
        }
        case OPSICK_HOME_PATH_HASH: {
            opsick_get_home(request);
            const uint64_t v = opsick_db_get_schema_version_number();
            break;
        }
        case OPSICK_PUBKEY_PATH_HASH: {
            opsick_get_pubkey(request);
            break;
        }
    }
}

void opsick_router_free()
{
    if (!initialized)
    {
        return;
    }
    initialized = 0;

    fio_stop();

    opsick_free_endpoint_home();
    opsick_free_endpoint_pubkey();
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