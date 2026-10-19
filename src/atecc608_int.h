// Module-internal helpers shared by src/atecc608.c (runtime API) and
// src/atecc608_prov.c (provisioning). Not part of the public surface.

#pragma once

#include "atecc608/atecc608_types.h"
#include "atca_status.h"

// Map a raw cryptoauthlib status onto the curated atecc608_status_t and
// record the raw code for atecc608_last_error(). The raw code is always
// preserved, so no diagnostic information is lost in the mapping.
atecc608_status_t atecc608_map_status(ATCA_STATUS atca_status);
