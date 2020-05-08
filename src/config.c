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

bool opsick_config_load()
{
    bool r = false;

    FILE* fp = fopen(OPSICK_CONFIG_FILE_PATH, "r");
    if (fp == NULL)
    {
        return false;
    }

    char errbuf[1024];
    memset(errbuf, '\0', sizeof(errbuf));

    toml_table_t* conf = toml_parse_file(fp, errbuf, sizeof(errbuf));
    fclose(fp);

    if (conf == NULL)
    {
        fprintf(stderr, "ERROR: Opsick failed to parse the user config TOML file \"%s\" - error buffer: %s", OPSICK_CONFIG_FILE_PATH, errbuf);
        return false;
    }

    toml_table_t* host = toml_table_in(conf, "host");
    if (host == NULL)
    {
        fprintf(stderr, "ERROR: The loaded opsick config file \"%s\" does not contain the mandatory \"[host]\" section!", OPSICK_CONFIG_FILE_PATH);
        goto exit;
    }

    hostsettings.log = false;
    hostsettings.port = 6677;
    hostsettings.threads = 2;
    hostsettings.max_clients = 0;
    hostsettings.max_header_size = 1024 * 16;
    hostsettings.max_body_size = 1024 * 1024 * 16;

    const char* log = toml_raw_in(host, "log");
    if (log != NULL)
    {
        hostsettings.log = opsick_strncmpic(log, "true", strlen(log)) == 0;
    }

    parse_toml_int(host, "port", (int64_t*)&hostsettings.port);
    parse_toml_int(host, "threads", (int64_t*)&hostsettings.threads);
    parse_toml_int(host, "max_clients", (int64_t*)&hostsettings.max_clients);
    parse_toml_int(host, "max_header_size", (int64_t*)&hostsettings.max_header_size);
    parse_toml_int(host, "max_body_size", (int64_t*)&hostsettings.max_body_size);

    toml_table_t* admin = toml_table_in(conf, "admin");
    if (admin == NULL)
    {
        fprintf(stderr, "ERROR: The loaded opsick config file \"%s\" does not contain the mandatory \"[admin]\" section!", OPSICK_CONFIG_FILE_PATH);
        goto exit;
    }

    // TODO: parse admin and pg settings here
    r = true;
exit:
    toml_free(conf);
    return r;
}