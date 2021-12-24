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

int main(void)
{
    PGconn* conn = PQconnectdb("hostaddr=127.0.0.1 port=5432 user=opsick_db_user password=kj775td-SnyYhKj8-7UqUC.8tC4nD dbname=opsick_db ");

    if (PQstatus(conn) == CONNECTION_BAD)
    {

        fprintf(stderr, "Connection to database failed: %s\n", PQerrorMessage(conn));
        return -1;
    }

    int ver = PQserverVersion(conn);

    printf("Server version: %d\n", ver);

    PQfinish(conn);
    return 0;

    if (!opsick_config_load())
    {
        fprintf(stderr, "ERROR: Opsick failed to open, read or parse the config file.");
        return EXIT_FAILURE;
    }

    opsick_db_init();
    opsick_keys_init();
    opsick_router_init();

    opsick_router_free();
    opsick_keys_free();
    opsick_db_free();

    return 0;
}
