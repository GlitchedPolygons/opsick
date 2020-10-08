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
#include "opsick/util.h"
#include "opsick/config.h"
#include "opsick/murmur3.h"
#include "opsick/constants.h"
#include "opsick/endpoints/home.h"
#include "opsick/endpoints/pubkey.h"
#include "opsick/endpoints/prvkey.h"
#include "opsick/endpoints/passwd.h"
#include "opsick/endpoints/useradd.h"
#include "opsick/endpoints/userdel.h"
#include "opsick/endpoints/user2fa.h"
#include "opsick/endpoints/version.h"

static void init_all_endpoints();
static void free_all_endpoints();
static void route_request(http_s*, uint32_t);

#pragma region INIT, ON_REQUEST AND FREE

// Read user config, start listening to HTTP requests
// on the user-defined port and start facil.io
void opsick_router_init()
{
    // Init utility functions and preallocate some strings.
    opsick_util_init();

    // Initialize endpoints.
    init_all_endpoints();

    // Start facil.io using the settings provided inside the user config.
    struct opsick_config_hostsettings hostsettings;
    opsick_config_get_hostsettings(&hostsettings);

    char port[64];
    memset(port, '\0', sizeof(port));
    sprintf(port, "%d", hostsettings.port);

    if (-1 == http_listen(port, NULL, .on_request = opsick_on_request, .max_header_size = hostsettings.max_header_size, .max_body_size = hostsettings.max_body_size, .max_clients = hostsettings.max_clients, .log = hostsettings.log))
    {
        fprintf(stderr, "Failure to start opsick on the given port '%s': perhaps the port is already in use?", port);
        exit(EXIT_FAILURE);
    }

    fio_start(.threads = hostsettings.threads);
}

void opsick_on_request(http_s* request)
{
    const FIOBJ path = request->path;
    if (!fiobj_type_is(path, FIOBJ_T_STRING))
    {
        http_send_error(request, 400);
        return;
    }

    const fio_str_info_s pathstr = fiobj_obj2cstr(path);
    const uint32_t pathstr_hash = murmur3(pathstr.data, (uint32_t)pathstr.len, OPSICK_MURMUR3_SEED);

    route_request(request, pathstr_hash);
}

void opsick_router_free()
{
    fio_stop();
    free_all_endpoints();
    opsick_util_free();
    printf("Goodbye :)");
}

#pragma endregion

static void route_request(http_s* request, const uint32_t pathstr_hash)
{
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
            break;
        }
        case OPSICK_PUBKEY_PATH_HASH: {
            opsick_get_pubkey(request);
            break;
        }
        case OPSICK_PRVKEY_PATH_HASH: {
            opsick_get_prvkey(request);
            break;
        }
        case OPSICK_PASSWD_PATH_HASH: {
            opsick_post_passwd(request);
            break;
        }
        case OPSICK_USERADD_PATH_HASH: {
            opsick_post_useradd(request);
            break;
        }
        case OPSICK_USERDEL_PATH_HASH: {
            opsick_post_userdel(request);
            break;
        }
        case OPSICK_USER2FA_PATH_HASH: {
            opsick_post_user2fa(request);
            break;
        }
        case OPSICK_VERSION_PATH_HASH: {
            opsick_get_version(request);
            break;
        }
    }
}

static void init_all_endpoints()
{
    opsick_init_endpoint_home();
    opsick_init_endpoint_pubkey();
    opsick_init_endpoint_prvkey();
    opsick_init_endpoint_passwd();
    opsick_init_endpoint_useradd();
    opsick_init_endpoint_userdel();
    opsick_init_endpoint_user2fa();
    opsick_init_endpoint_version();
}

static void free_all_endpoints()
{
    opsick_free_endpoint_home();
    opsick_free_endpoint_pubkey();
    opsick_free_endpoint_prvkey();
    opsick_free_endpoint_passwd();
    opsick_free_endpoint_useradd();
    opsick_free_endpoint_userdel();
    opsick_free_endpoint_user2fa();
    opsick_free_endpoint_version();
}
