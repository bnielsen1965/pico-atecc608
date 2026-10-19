cmake_minimum_required(VERSION 3.13)

# Board: Raspberry Pi Pico 2 (RP2350). Must be set before including the SDK,
# since the SDK reads it at configure time.
set(PICO_BOARD pico2)

# Core: defaults to the Cortex-M33 cores (rp2350-arm-s). The RP2350's two
# cores can each run either Cortex-M33 or Hazard3 RISC-V, and pico_multicore
# supports both, so this builds and runs on either platform:
#   -DPICO_PLATFORM=rp2350-arm-s   -> two Cortex-M33 cores  (build/)
#   -DPICO_PLATFORM=rp2350-riscv   -> two Hazard3 RISC-V cores (build-riscv/)
# Changing the platform requires a fresh build directory per platform.
if (NOT PICO_PLATFORM)
    set(PICO_PLATFORM rp2350-arm-s)
endif()

# Location of the Pico SDK. Override with -DPICO_SDK_PATH=... if you move it.
set(PICO_SDK_PATH "$ENV{HOME}/Projects/pico-sdk" CACHE PATH "Path to the Raspberry Pi Pico SDK")

include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico-atecc608 C CXX ASM)

# C11 matters: newer GCCs default to C23, where an empty function prototype `()`
# means `(void)` and conflicts with the pico-command-line declarations.
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

pico_sdk_init()

# ============================================================================
# cryptoauthlib — fetched at build time; NEVER vendored in this repo
# (Decision 7).
#
# We pull only the *source* and build the core ourselves. cryptoauthlib's own
# CMake picks its HAL by *build host* (it force-adds the Linux host HAL on any
# UNIX machine), which is wrong for a bare-metal cross-target. Building the
# core directly lets us (a) drop the host-only files and (b) supply our own
# RP2350 I2C HAL (Phase 2). Nothing from cryptoauthlib is stored in this repo.
#
# Air-gapped build: -DCRYPTOAUTHLIB_SOURCE_DIR=<path to a local clone> (still
# not committed to this repo).
# ============================================================================
include(FetchContent)
# We deliberately use FetchContent_Populate (source only, no add_subdirectory)
# so cryptoauthlib's host-keyed CMake does not run. That form is deprecated
# under CMP0169 (which prefers MakeAvailable); pin it OLD to keep source-only.
if (POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
if (CRYPTOAUTHLIB_SOURCE_DIR)
    FetchContent_Declare(cryptoauthlib SOURCE_DIR ${CRYPTOAUTHLIB_SOURCE_DIR})
else()
    FetchContent_Declare(
        cryptoauthlib
        GIT_REPOSITORY https://github.com/microchiptech/cryptoauthlib
        GIT_TAG v3.8.0
        GIT_SHALLOW TRUE
    )
endif()
FetchContent_GetProperties(cryptoauthlib)
if (NOT cryptoauthlib_POPULATED)
    message(STATUS "Fetching cryptoauthlib source (build-time only, not vendored)...")
    FetchContent_Populate(cryptoauthlib)
endif()

set(CAL ${cryptoauthlib_SOURCE_DIR}/lib)

# Generate atca_config.h for the devices/features we use. Mirrors what
# cryptoauthlib's per-device checks.cmake would set, minus the host-only bits.
set(ATCA_ATECC608_SUPPORT  ON)   # ATECC608 / 608B / 608A / 608C (device type 3)
set(ATCA_ATECC508A_SUPPORT ON)   # compatibility chain
set(ATCA_ATECC108A_SUPPORT ON)
set(ATCA_ATSHA206A_SUPPORT ON)   # legacy, pulls in app/api_206a
set(ATCA_CA_SUPPORT        ON)
set(ATCA_CHECK_PARAMS_EN   ON)
# Phase 2: the module supplies the RP2350 I2C HAL (src/hal_rp2350.c), and
# the atcab_* basic API layer is compiled for the demo console.
set(ATCA_HAL_I2C           ON)
set(ATCA_USE_ATCAB_FUNCTIONS ON)
# newlib (the Pico C library) provides these. (strcasestr is a GNU extension
# newlib does not declare, so we leave ATCA_PLATFORM_STRCASESTR undefined and
# let cryptoauthlib use its own lib_strcasestr fallback in atca_helpers.c.)
set(ATCA_PLATFORM_MALLOC malloc)
set(ATCA_PLATFORM_FREE   free)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cryptoauth_core)
configure_file(
    ${CAL}/atca_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoauth_core/atca_config.h
    @ONLY
)

# The portable core sources (everything cryptoauthlib compiles by default,
# minus the host-specific hal/hal_linux.c).
file(GLOB            CA_TOP_SRC      ${CAL}/atca_*.c ${CAL}/cal_buffer.c)
file(GLOB            CA_ATCACERT_SRC ${CAL}/atcacert/*.c)
file(GLOB            CA_CALIB_SRC    ${CAL}/calib/*.c)
file(GLOB_RECURSE    CA_CRYPTO_SRC   ${CAL}/crypto/*.c)
file(GLOB            CA_HOST_SRC     ${CAL}/host/*.c)
set(CA_HAL_SRC             ${CAL}/hal/atca_hal.c)
set(CA_API206_SRC          ${cryptoauthlib_SOURCE_DIR}/app/api_206a/api_206a.c)

# Our RP2350 I2C HAL is compiled INTO this target rather than into the
# atecc608 library: atca_hal.c in this archive references the hal_i2c_*
# symbols, and a static archive cannot satisfy references from an archive
# listed earlier on the link line (single-pass resolution).
add_library(cryptoauth_core STATIC
    ${CA_TOP_SRC}
    ${CA_ATCACERT_SRC}
    ${CA_CALIB_SRC}
    ${CA_CRYPTO_SRC}
    ${CA_HOST_SRC}
    ${CA_HAL_SRC}
    ${CA_API206_SRC}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hal_rp2350.c
)
# NOTE: no C_STANDARD override — the project default is C11, which the
# pico-sdk headers (hardware/i2c.h, pulled in by our HAL source) require
# for static_assert. cryptoauthlib itself compiles fine under C11.
# The HAL needs the pico-sdk (hardware_i2c, stdlib); PUBLIC so consuming
# targets inherit the include paths and the final link.
target_link_libraries(cryptoauth_core PUBLIC
    pico_stdlib
    hardware_i2c
)
target_include_directories(cryptoauth_core PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoauth_core
    ${CAL}
    ${CAL}/hal
    ${CAL}/calib
    ${CAL}/crypto
    ${CAL}/crypto/hashes
    ${CAL}/host
    ${CAL}/atcacert
    ${cryptoauthlib_SOURCE_DIR}/app/api_206a
)

# ============================================================================
# module library
# ============================================================================
# Phase 3: the module exposes the curated atecc608_* core API (public
# header in include/atecc608/, implementation in src/atecc608.c) over
# cryptoauthlib; the RP2350 I2C HAL (src/hal_rp2350.*) is module-internal
# and lives in the cryptoauth_core target (see above).
# Phase 4A adds the pure-logic config-zone builder (atecc608_config.c) and
# the guarded provisioning API (atecc608_prov.c); both are HAL-agnostic and
# are unit-tested on the host in tests/ (mock chip, no Pico).
add_library(atecc608 STATIC
    src/atecc608.c
    src/atecc608_config.c
    src/atecc608_prov.c
    src/atecc608_status.c
)
# Public: consumers get the API header. Private: our implementation files
# also need the module-internal HAL header; it is not part of the public
# surface.
target_include_directories(atecc608
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(atecc608 PUBLIC
    cryptoauth_core   # brings pico_stdlib + hardware_i2c transitively
)

# Single, namespaced target for consuming projects to link against.
add_library(atecc608::atecc608 ALIAS atecc608)

# ============================================================================
# command-line framework + demo app
# ============================================================================
add_subdirectory(pico-command-line)
add_subdirectory(app)
