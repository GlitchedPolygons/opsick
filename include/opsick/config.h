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

/**
 * Opens the "opsick.conf" file,
 * reads the user-defined preferences/settings in it
 * and loads them into memory.
 * @return Whether loading the opsick config from disk succeeded (1) or not (0).
 */
int opsick_load_config();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OPSICK_CONFIG_H
