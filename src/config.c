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
    hostsettings.log = opsick_strncmpic(log, "true", strlen(log)) == 0;

    const char* port = toml_raw_in(host, "port");
    if (port != NULL && toml_rtoi(port, (int64_t*)&hostsettings.port))
    {
        fprintf(stderr, "ERROR: Failed to parse \"port\" setting inside config - \"%s\" is not a valid port number!", port);
        goto exit;
    }

    const char* threads = toml_raw_in(host, "threads");
    if (threads != NULL && toml_rtoi(threads, (int64_t*)&hostsettings.threads))
    {
        fprintf(stderr, "ERROR: Failed to parse \"threads\" setting inside config - \"%s\" is not a valid integer!", threads);
        goto exit;
    }

    r = true;
exit:
    toml_free(conf);
    return r;
}