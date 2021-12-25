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
#include "opsick/config.h"
#include "opsick/router.h"
#include "opsick/keys.h"
#include "opsick/db.h"

int main(const int argc, const char* argv[])
{
    char opsick_db_connection_string_filepath[1024] = { 0x00 };
    strncpy(opsick_db_connection_string_filepath, (argc > 1 ? argv[1] : OPSICK_DEFAULT_DBCONN_FILE), sizeof(opsick_db_connection_string_filepath));

    if (!opsick_db_init(opsick_db_connection_string_filepath))
    {
        fprintf(stderr, "ERROR: Opsick failed to initialize the db connection. \n");
        return -1;
    }

    if (!opsick_config_load())
    {
        fprintf(stderr, "ERROR: Opsick failed to load the config from db. \n");
        return -2;
    }

    opsick_keys_init();
    opsick_router_init();

    // ===================

    opsick_router_free();
    opsick_keys_free();
    opsick_db_free();

    return 0;
}
