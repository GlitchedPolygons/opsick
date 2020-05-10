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

#include <string.h>
#include <tomlc99/toml.h>
#include "opsick/config.h"
#include "opsick/constants.h"
#include "opsick/strncmpic.h"

static struct opsick_config_hostsettings hostsettings;
static struct opsick_config_adminsettings adminsettings;
static struct opsick_config_pgsettings pgsettings;

static inline void parse_toml_int(toml_table_t* toml_table, const char* setting, int64_t* out)
{
    const char* value = toml_raw_in(toml_table, setting);
    if (value != NULL && toml_rtoi(value, out) != 0)
    {
        fprintf(stderr, "ERROR: Failed to parse \"%s\" setting inside config - \"%s\" is not a valid integer!", setting, value);
    }
}

static inline void parse_toml_uint(toml_table_t* toml_table, const char* setting, uint64_t* out)
{
    const char* value = toml_raw_in(toml_table, setting);
    if (value != NULL && toml_rtou(value, out) != 0)
    {
        fprintf(stderr, "ERROR: Failed to parse \"%s\" setting inside config - \"%s\" is not a valid unsigned integer!", setting, value);
    }
}

static inline void tablerr(const char* tablename)
{
    fprintf(stderr, "ERROR: The loaded opsick config file \"%s\" does not contain the mandatory \"[%s]\" section!", OPSICK_CONFIG_FILE_PATH, tablename);
}

static inline void init()
{
    memset(&hostsettings, '\0', sizeof(hostsettings));
    memset(&adminsettings, '\0', sizeof(adminsettings));
    memset(&pgsettings, '\0', sizeof(pgsettings));

    hostsettings.log = false;
    hostsettings.port = 6677;
    hostsettings.threads = 2;
    hostsettings.max_clients = 0;
    hostsettings.max_header_size = 1024 * 16;
    hostsettings.max_body_size = 1024 * 1024 * 16;

    adminsettings.max_users = 0;
    adminsettings.use_index_html = true;
    adminsettings.key_refresh_interval_hours = 72;
    strcpy(adminsettings.user_registration_password, "opsick_registration_password");

    pgsettings.port = 5432;
    pgsettings.connect_timeout = 60;
    strcpy(pgsettings.host, "localhost");
    strcpy(pgsettings.dbname, "opsick_pg_db");
    strcpy(pgsettings.user, "opsick_pg_user");
    strcpy(pgsettings.password, "opsick_pg_db_password");
}

static bool load_hostsettings(toml_table_t* conf)
{
    toml_table_t* table;
    const char tablename[] = "host";

    table = toml_table_in(conf, tablename);
    if (table == NULL)
    {
        tablerr(tablename);
        return false;
    }

    hostsettings.log = opsick_strncmpic(toml_raw_in(table, "log"), "true", 4) == 0;

    uint64_t port = -1;
    parse_toml_uint(table, "port", &port);
    if (port > 0 && port <= 65535)
    {
        hostsettings.port = (uint16_t)port;
    }
    else
    {
        fprintf(stderr, "ERROR: The parsed port number \"%ld\" is not within the range of valid port numbers [0; 65535] - using default value of \"%d\" instead...", port, hostsettings.port);
    }

    uint64_t threads = -1;
    parse_toml_uint(table, "threads", &threads);
    if (threads > 0 && threads <= 64)
    {
        hostsettings.threads = (uint8_t)threads;
    }
    else
    {
        fprintf(stderr, "ERROR: The parsed maximum thread count setting \"%lu\" is not within the range of recommended thread count limits [1; 64] - using default thread count of \"%d\" instead...", threads, hostsettings.threads);
    }

    parse_toml_uint(table, "max_clients", &hostsettings.max_clients);
    parse_toml_uint(table, "max_header_size", &hostsettings.max_header_size);
    parse_toml_uint(table, "max_body_size", &hostsettings.max_body_size);

    return true;
}

static bool load_adminsettings(toml_table_t* conf)
{
    const char tablename[] = "admin";

    toml_table_t* table = toml_table_in(conf, tablename);
    if (table == NULL)
    {
        tablerr(tablename);
        return false;
    }

    parse_toml_uint(table, "max_users", &adminsettings.max_users);
    parse_toml_uint(table, "key_refresh_interval_hours", &adminsettings.key_refresh_interval_hours);
    adminsettings.use_index_html = opsick_strncmpic(toml_raw_in(table, "use_index_html"), "true", 4) == 0;

    char* user_registration_password = NULL;
    if (toml_rtos(toml_raw_in(table, "user_registration_password"), &user_registration_password))
    {
        fprintf(stderr, "ERROR: Failed to parse \"user_registration_password\" setting string from the opsick user config file \"%s\".", OPSICK_CONFIG_FILE_PATH);
    }
    else
    {
        strncpy(adminsettings.user_registration_password, user_registration_password, sizeof(adminsettings.user_registration_password));
    }
    free(user_registration_password);

    return true;
}

static bool load_pgsettings(toml_table_t* conf)
{
    const char tablename[] = "postgres";

    toml_table_t* table = toml_table_in(conf, tablename);
    if (table == NULL)
    {
        tablerr(tablename);
        return false;
    }

    uint64_t port = 5432;
    parse_toml_uint(table, "port", &port);
    if (port > 0 && port <= 65535)
    {
        pgsettings.port = (uint16_t)port;
    }
    else
    {
        pgsettings.port = 5432;
        fprintf(stderr, "ERROR: The parsed postgres port setting \"%lu\" is not within the range of valid port numbers [0; 65535] - using postgres' default value of 5432 ", port);
    }

    uint64_t connect_timeout = 60;
    parse_toml_uint(table, "connect_timeout", &connect_timeout);
    if (connect_timeout > 300)
    {
        fprintf(stderr, "WARNING: Using a postgres \"connect_timeout\" value of >300 is not recommended! Please set this to a reasonable value inside opsick's config TOML file!");
    }
    if (connect_timeout > UINT16_MAX)
    {
        connect_timeout = UINT16_MAX;
    }
    pgsettings.connect_timeout = (uint16_t)connect_timeout;

    char* host = NULL;
    if (toml_rtos(toml_raw_in(table, "host"), &host))
    {
        fprintf(stderr, "ERROR: Failed to parse postgres \"host\" setting string from the opsick user config file \"%s\". Using default value of \"%s\" instead...", OPSICK_CONFIG_FILE_PATH, pgsettings.host);
    }
    else
    {
        strncpy(pgsettings.host, host, sizeof(pgsettings.host));
    }

    char* dbname = NULL;
    if (toml_rtos(toml_raw_in(table, "dbname"), &dbname))
    {
        fprintf(stderr, "ERROR: Failed to parse postgres \"dbname\" setting string from the opsick user config file \"%s\". Using default value of \"%s\" instead...", OPSICK_CONFIG_FILE_PATH, pgsettings.dbname);
    }
    else
    {
        strncpy(pgsettings.dbname, dbname, sizeof(pgsettings.dbname));
    }

    char* user = NULL;
    if (toml_rtos(toml_raw_in(table, "user"), &user))
    {
        fprintf(stderr, "ERROR: Failed to parse postgres \"user\" setting string from the opsick user config file \"%s\". Using default value of \"%s\" instead...", OPSICK_CONFIG_FILE_PATH, pgsettings.user);
    }
    else
    {
        strncpy(pgsettings.user, user, sizeof(pgsettings.user));
    }

    char* password = NULL;
    if (toml_rtos(toml_raw_in(table, "password"), &password))
    {
        fprintf(stderr, "ERROR: Failed to parse postgres \"password\" setting string from the opsick user config file \"%s\". Using default value of \"%s\" instead...", OPSICK_CONFIG_FILE_PATH, pgsettings.password);
    }
    else
    {
        strncpy(pgsettings.password, password, sizeof(pgsettings.password));
    }

    free(host);
    free(dbname);
    free(user);
    free(password);
    return true;
}

bool opsick_config_load()
{
    init();

    bool r;
    FILE* fp;
    toml_table_t* conf;
    char errbuf[1024];
    memset(errbuf, '\0', sizeof(errbuf));

    r = false;

    fp = fopen(OPSICK_CONFIG_FILE_PATH, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "ERROR: Opsick failed to open the user config TOML file \"%s\". Invalid/inexistent file path?", OPSICK_CONFIG_FILE_PATH);
        return false;
    }

    conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (conf == NULL)
    {
        fprintf(stderr, "ERROR: Opsick failed to parse the user config TOML file \"%s\" - error buffer: %s", OPSICK_CONFIG_FILE_PATH, errbuf);
        return false;
    }

    if (!load_hostsettings(conf))
    {
        goto exit;
    }

    if (!load_adminsettings(conf))
    {
        goto exit;
    }

    if (!load_pgsettings(conf))
    {
        goto exit;
    }

    r = true;

exit:
    toml_free(conf);
    return r;
}

bool opsick_config_get_hostsettings(struct opsick_config_hostsettings* out)
{
    if (out == NULL)
    {
        return false;
    }
    struct opsick_config_hostsettings t = hostsettings;
    *out = t;
    return true;
}

bool opsick_config_get_adminsettings(struct opsick_config_adminsettings* out)
{
    if (out == NULL)
    {
        return false;
    }
    struct opsick_config_adminsettings t = adminsettings;
    *out = t;
    return true;
}

bool opsick_config_get_pgsettings(struct opsick_config_pgsettings* out)
{
    if (out == NULL)
    {
        return false;
    }
    struct opsick_config_pgsettings t = pgsettings;
    *out = t;
    return true;
}
