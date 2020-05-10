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
    const char tablename[] = "host";

    toml_table_t* table = toml_table_in(conf, tablename);
    if (table == NULL)
    {
        tablerr(tablename);
        return false;
    }

    hostsettings.log = opsick_strncmpic(toml_raw_in(table, "log"), "true", 4) == 0;
    parse_toml_int(table, "port", (int64_t*)&hostsettings.port);
    parse_toml_int(table, "threads", (int64_t*)&hostsettings.threads);
    parse_toml_int(table, "max_clients", (int64_t*)&hostsettings.max_clients);
    parse_toml_int(table, "max_header_size", (int64_t*)&hostsettings.max_header_size);
    parse_toml_int(table, "max_body_size", (int64_t*)&hostsettings.max_body_size);

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

    // TODO: use toml_rtos instead of this strcpy to let it handle the quotes

    parse_toml_int(table, "max_users", (int64_t*)&adminsettings.max_users);
    parse_toml_int(table, "key_refresh_interval_hours", (int64_t*)&adminsettings.key_refresh_interval_hours);
    adminsettings.use_index_html = opsick_strncmpic(toml_raw_in(table, "use_index_html"), "true", 4) == 0;
    strcpy(adminsettings.user_registration_password, toml_raw_in(table, "user_registration_password"));

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

    parse_toml_int(table, "port", (int64_t*)&pgsettings.port);
    parse_toml_int(table, "connect_timeout", (int64_t*)&pgsettings.connect_timeout);
    strcpy(pgsettings.host, toml_raw_in(table, "host"));
    strcpy(pgsettings.dbname, toml_raw_in(table, "dbname"));
    strcpy(pgsettings.user, toml_raw_in(table, "user"));
    strcpy(pgsettings.password, toml_raw_in(table, "password"));

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
