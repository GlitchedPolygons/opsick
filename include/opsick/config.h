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

#ifndef OPSICK_CONFIG_H
#define OPSICK_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "opsick/constants.h"

/**
 * Opens the opsick config file,
 * reads the user-defined preferences/settings in it
 * and loads them into memory.
 * @return Whether loading the opsick config from disk succeeded or not.
 */
bool opsick_config_load();

/**
 * The host section of the opsick config file (port number, max. HTTP header size, etc...).
 */
struct opsick_config_hostsettings
{
    /**
     * Should HTTP requests be logged? <p>
     * [DEFAULT] <c>false</c>
     */
    bool log;

    /**
     * The port number on which opsick should listen for requests. <p>
     * [DEFAULT] <c>6677</c>
     */
    uint16_t port;

    /**
     * The number of threads to dedicate to opsick. <p>
     * [DEFAULT] <c>2</c>
     */
    uint8_t threads;

    /**
     * The maximum number of clients that are allowed to connect concurrently. <p>
     * [DEFAULT] Computed automatically by facil.io (if this value is left at <c>0</c>).
     */
    uint64_t max_clients;

    /**
     * The maximum HTTP header size. <p>
     * [DEFAULT] <c>16KB</c> (<c>1024 * 16B</c>).
     */
    uint64_t max_header_size;

    /**
     * The maximum request body size. <p>
     * [DEFAULT] <c>16MB</c> (<c>1024 * 1024 * 16B</c>).
     */
    size_t max_body_size;
};

/**
 * Gets the current host settings from the <c>[host]</c> section inside the opsick config file (as a copy, so it's read-only).
 * @param out An opsick_config_hostsettings instance into which to write the parsed config values. If retrieval fails in any way, this is left untouched!
 * @return <c>true</c> if retrieval succeeded; <c>false</c> if retrieval failed due to invalid arguments (e.g. <c>NULL</c>).
 */
bool opsick_config_get_hostsettings(struct opsick_config_hostsettings* out);

// ---------------------------------------------------------------------------------------------------

/**
 * The admin section of the opsick config file.
 */
struct opsick_config_adminsettings
{
    /**
     * The maximum amount of users the opsick instance is allowed to have
     * (if this limit is reached, the registration endpoint is disabled). <p>
     * [DEFAULT] <c>0</c> (which means unlimited).
     */
    uint64_t max_users;

    /**
     * Set this to <c>true</c> if you want to let the home endpoint (reachable under "/")
     * serve the index.html file that's located inside the directory where the opsick executable resides. <p>
     * You could for example modify that index.html file and customize it to your needs,
     * add some sort of welcome screen to your users and basically do whatever you like with it. <p>
     * If set to <c>false</c>, the "/" endpoint just returns a plain HTTP status code 200 ("OK").
     * In that case, the whole opsick instance would act as a plain Web API without any visual feedback/interface. <p>
     * [DEFAULT] <c>true</c>
     */
    bool use_index_html;

    /**
     * Define the interval (in hours) at which the opsick server keys are auto-replaced with freshly generated ones. <p>
     * These keys (one pair of public and private key) are used by the server to sign HTTP responses (private key),
     * and by the clients to verify the HTTP responses' signature (public key). <p>
     * [DEFAULT] <c>72</c> (after 72 hours the server keys are regenerated and the old ones discarded).
     */
    uint32_t key_refresh_interval_hours;

    /**
     * Define a password that is needed in order to register a new user. <p>
     * [DEFAULT] <c>opsick_registration_password</c>
     */
    char user_registration_password[OPSICK_MAX_USER_CREATION_PASSWORD_LENGTH];
};

/**
 * Gets the current admin settings from the <c>[admin]</c> section inside the opsick config file (as a copy, so it's read-only).
 * @param out An opsick_config_adminsettings instance into which to write the parsed config values. If retrieval fails in any way, this is left untouched!
 * @return <c>true</c> if retrieval succeeded; <c>false</c> if retrieval failed due to invalid arguments (e.g. <c>NULL</c>).
 */
bool opsick_config_get_adminsettings(struct opsick_config_adminsettings* out);

// ---------------------------------------------------------------------------------------------------

/**
 * The postgres section of the config file.
 */
struct opsick_config_pgsettings
{
    /**
     * Postgres host to connect to (e.g. a raw IP address or a domain such as <c>postgres.example.com</c>). <p>
     * [DEFAULT] <c>localhost</c>
     */
    char host[OPSICK_MAX_PG_HOST_LENGTH];

    /**
     * The port number to connect to on the specified pg host. <p>
     * [DEFAULT] <c>5432</c>
     */
    uint16_t port;

    /**
     * The name of the postgres database to connect to. <p>
     * [DEFAULT] <c>opsick_pg_db</c>
     */
    char dbname[OPSICK_MAX_PG_DBNAME_LENGTH];

    /**
     * The name of the postgres user. <p>
     * [DEFAULT] <c>opsick_pg_user</c>
     */
    char user[OPSICK_MAX_PG_USER_LENGTH];

    /**
     * The opsick postgres user's password. PLEASE REPLACE THIS VALUE AS SOON AS POSSIBLE AFTER INSTALLATION! <p>
     * [DEFAULT] <c>opsick_pg_db_password</c>.
     */
    char password[OPSICK_MAX_PG_PASSWORD_LENGTH];

    /**
     * Postgres maximum connection timeout to wait for in seconds. <p>
     * [DEFAULT] <c>60</c>
     */
    uint16_t connect_timeout;
};

/**
 * Gets the current postgres connection settings from the <c>[postgres]</c> section inside the opsick config file (as a copy, so it's read-only).
 * @param out An opsick_config_pgsettings instance into which to write the parsed config values. If retrieval fails in any way, this is left untouched!
 * @return <c>true</c> if retrieval succeeded; <c>false</c> if retrieval failed due to invalid arguments (e.g. <c>NULL</c>).
 */
bool opsick_config_get_pgsettings(struct opsick_config_pgsettings* out);

// ---------------------------------------------------------------------------------------------------

/**
 * Gets an integer setting from the user config.
 * @param name The name of the numeric setting you're trying to retrieve.
 * @param out Where to write the found integer value into. If retrieval fails in any way, this is left untouched!
 * @return 1 if retrieval succeeded; 0 if retrieval failed due to the setting not being found; -1 if due to a parsing failure; -2 if due to invalid arguments (e.g. <c>NULL</c>).
 */
int opsick_config_get_integer(const char* name, int64_t* out);

/**
 * Gets a floating point setting from the user config.
 * @param name The name of the numeric setting you're trying to retrieve.
 * @param out Where to write the found floating point number into. If retrieval fails in any way, this is left untouched!
 * @return 1 if retrieval succeeded; 0 if retrieval failed due to the setting not being found; -1 if due to a parsing failure; -2 if due to invalid arguments (e.g. <c>NULL</c>).
 */
int opsick_config_get_number(const char* name, double* out);

/**
 * Gets a boolean setting from the config.
 * @param name The name of the boolean setting you're trying to retrieve.
 * @param out Where to write the found boolean into. If retrieval fails in any way, this is left untouched!
 * @return 1 if retrieval succeeded; 0 if retrieval failed due to the setting not being found; -1 if due to a parsing failure; -2 if due to invalid arguments (e.g. <c>NULL</c>).
 */
int opsick_config_get_boolean(const char* name, bool* out);

/**
 * Gets a setting from the opsick user config.
 * @param name The name/key of the setting to retrieve.
 * @return The found setting's string value; <c>NULL</c> if no such setting was found inside the config (or if the name parameter was <c>NULL</c>).
 */
const char* opsick_config_get_string(const char* name);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONFIG_H
