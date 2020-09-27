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

#include "opsick/keys.h"
#include "opsick/endpoints/pubkey.h"

static FIOBJ ed25519_header;
static FIOBJ curve448_header;

void opsick_init_endpoint_pubkey()
{
    ed25519_header = fiobj_str_new("ed25519-public-key", 18);
    fiobj_str_freeze(ed25519_header);

    curve448_header = fiobj_str_new("curve448-public-key", 19);
    fiobj_str_freeze(curve448_header);
}

void opsick_get_pubkey(http_s* request)
{
    struct opsick_ed25519_keypair ed25519;
    struct cecies_curve448_keypair curve448;

    opsick_keys_get_ed25519_keypair(&ed25519);
    opsick_keys_get_curve448_keypair(&curve448);

    http_set_header(request, ed25519_header, fiobj_str_new(ed25519.public_key_hexstr, 64));
    http_set_header(request, curve448_header, fiobj_str_new(curve448.public_key.hexstring, 112));
    http_finish(request);
}

void opsick_free_endpoint_pubkey()
{
    fiobj_free(ed25519_header);
    fiobj_free(curve448_header);
}