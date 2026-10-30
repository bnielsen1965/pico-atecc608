# Host unit tests for the ATECC608 module (Phase 4A).
#
# Standalone host build: no pico-sdk, no chip. The cryptoauthlib core is
# compiled exactly as in the top-level build, except the RP2350 I2C HAL is
# replaced by the mock chip (mock_chip.c), which provides the same
# hal_i2c_* / hal_delay_* symbols.
#
#   cmake -S tests -B tests/build
#   cmake --build tests/build
#   ctest --test-dir tests/build
#
# Air-gapped build: -DCRYPTOAUTHLIB_SOURCE_DIR=<path to a local clone>.

cmake_minimum_required(VERSION 3.13)
project(atecc608_host_tests C)

# C11 to match the top-level build (cryptoauthlib compiles fine under C11).
set(CMAKE_C_STANDARD 11)

# --- cryptoauthlib: same fetch rules as the top-level build ----------------
include(FetchContent)
# FetchContent_Populate (source only, no add_subdirectory) so cryptoauthlib's
# host-keyed CMake does not run; pin CMP0169 OLD (same as the top level).
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

# Same feature set as the top-level atca_config.h.
set(ATCA_ATECC608_SUPPORT  ON)
set(ATCA_ATECC508A_SUPPORT ON)
set(ATCA_ATECC108A_SUPPORT ON)
set(ATCA_ATSHA206A_SUPPORT ON)
set(ATCA_CA_SUPPORT        ON)
set(ATCA_CHECK_PARAMS_EN   ON)
set(ATCA_HAL_I2C           ON)
set(ATCA_USE_ATCAB_FUNCTIONS ON)
set(ATCA_PLATFORM_MALLOC malloc)
set(ATCA_PLATFORM_FREE   free)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cryptoauth_core)
configure_file(
    ${CAL}/atca_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/cryptoauth_core/atca_config.h
    @ONLY
)

file(GLOB            CA_TOP_SRC      ${CAL}/atca_*.c ${CAL}/cal_buffer.c)
file(GLOB            CA_ATCACERT_SRC ${CAL}/atcacert/*.c)
file(GLOB            CA_CALIB_SRC    ${CAL}/calib/*.c)
file(GLOB_RECURSE    CA_CRYPTO_SRC   ${CAL}/crypto/*.c)
file(GLOB            CA_HOST_SRC     ${CAL}/host/*.c)
set(CA_HAL_SRC             ${CAL}/hal/atca_hal.c)
set(CA_API206_SRC          ${cryptoauthlib_SOURCE_DIR}/app/api_206a/api_206a.c)

# cryptoauthlib core for the host: the same source set as the top-level
# cryptoauth_core target, minus the RP2350 HAL (the mock provides it).
add_library(ca_host STATIC
    ${CA_TOP_SRC}
    ${CA_ATCACERT_SRC}
    ${CA_CALIB_SRC}
    ${CA_CRYPTO_SRC}
    ${CA_HOST_SRC}
    ${CA_HAL_SRC}
    ${CA_API206_SRC}
)
target_include_directories(ca_host PUBLIC
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

set(MOD_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# The mock chip + mock HAL (ours: strict warnings). It includes only
# atecc608_types.h from the module (geometry constants), never the prov/config
# headers.
add_library(mock_chip STATIC mock_chip.c)
target_include_directories(mock_chip PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MOD_ROOT}/include
)
target_link_libraries(mock_chip PUBLIC ca_host)
target_compile_options(mock_chip PRIVATE -Wall -Wextra)

# The module under test: the HAL-agnostic Phase 4A/5 sources only.
# (src/atecc608.c is excluded — it needs the RP2350 HAL / pico-sdk.)
add_library(atecc608_host STATIC
    ${MOD_ROOT}/src/atecc608_config.c
    ${MOD_ROOT}/src/atecc608_crypto.c
    ${MOD_ROOT}/src/atecc608_prov.c
    ${MOD_ROOT}/src/atecc608_status.c
)
target_include_directories(atecc608_host
    PUBLIC  ${MOD_ROOT}/include
    PRIVATE ${MOD_ROOT}/src
)
target_link_libraries(atecc608_host PUBLIC ca_host)
target_compile_options(atecc608_host PRIVATE -Wall -Wextra)

enable_testing()

# Both executables link the three libraries as a group: the hal_i2c_* /
# hal_delay_* symbols live in mock_chip while cryptoauthlib (ca_host)
# references them, so plain left-to-right static linking can drop objects
# that nothing directly references (e.g. in test_config, which only calls
# atCRC). --start-group makes the linker iterate until everything resolves.
add_executable(test_config test_config.c)
target_link_libraries(test_config PRIVATE
    -Wl,--start-group atecc608_host mock_chip ca_host -Wl,--end-group
)
target_compile_options(test_config PRIVATE -Wall -Wextra)
add_test(NAME test_config COMMAND $<TARGET_FILE:test_config>)

add_executable(test_prov test_prov.c)
target_link_libraries(test_prov PRIVATE
    -Wl,--start-group atecc608_host mock_chip ca_host -Wl,--end-group
)
target_compile_options(test_prov PRIVATE -Wall -Wextra)
add_test(NAME test_prov COMMAND $<TARGET_FILE:test_prov>)

add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE
    -Wl,--start-group atecc608_host mock_chip ca_host -Wl,--end-group
)
target_compile_options(test_crypto PRIVATE -Wall -Wextra)
add_test(NAME test_crypto COMMAND $<TARGET_FILE:test_crypto>)

# The vault example's software AES-256-GCM (example/vault/vault_gcm.c) is
# pure C — no pico-sdk, no cryptoauthlib — so it is host-verified here
# against the NIST GCM vectors; it links nothing but its own sources.
add_executable(test_vault_gcm test_vault_gcm.c ${MOD_ROOT}/example/vault/vault_gcm.c)
target_include_directories(test_vault_gcm PRIVATE ${MOD_ROOT}/example/vault)
target_compile_options(test_vault_gcm PRIVATE -Wall -Wextra)
add_test(NAME test_vault_gcm COMMAND $<TARGET_FILE:test_vault_gcm>)

# The fido2 example's CTAPHID transport (example/fido2/fido_ctaphid.c) is
# likewise pure C — no pico-sdk, no TinyUSB — so the framing/channel state
# machine is host-verified here: INIT allocation/sync, PING echo (single
# and multi-packet, up to the 7609-byte maximum), the CTAP2 error table,
# the busy/timeout rules, and keep-alive throttling.
add_executable(test_ctaphid test_ctaphid.c ${MOD_ROOT}/example/fido2/fido_ctaphid.c)
target_include_directories(test_ctaphid PRIVATE ${MOD_ROOT}/example/fido2)
target_compile_options(test_ctaphid PRIVATE -Wall -Wextra)
add_test(NAME test_ctaphid COMMAND $<TARGET_FILE:test_ctaphid>)

# The fido2 example's CBOR codec (example/fido2/fido_cbor.c) is pure C:
# RFC 8949 known-answer vectors (the same set the spec's appendix uses),
# the CTAP2 canonical-form rules (shortest encoding, definite lengths,
# no tags), decode round-trips, and the error paths (truncation,
# indefinite lengths, non-canonical integers, encoder overflow).
add_executable(test_cbor test_cbor.c ${MOD_ROOT}/example/fido2/fido_cbor.c)
target_include_directories(test_cbor PRIVATE ${MOD_ROOT}/example/fido2)
target_compile_options(test_cbor PRIVATE -Wall -Wextra)
add_test(NAME test_cbor COMMAND $<TARGET_FILE:test_cbor>)

# The fido2 example's CTAP2 dispatch (example/fido2/fido_ctap.c) is
# likewise pure C: the 6-byte header validation (length, version,
# wLength), GET_INFO (the full response map, decoded field by field,
# plus a hand-computed byte KAT), and the unimplemented-command answer
# (CTAP1_ERR_INVALID_COMMAND, the spec's MUST).
add_executable(test_ctap test_ctap.c
            ${MOD_ROOT}/example/fido2/fido_ctap.c
            ${MOD_ROOT}/example/fido2/fido_cbor.c)
target_include_directories(test_ctap PRIVATE ${MOD_ROOT}/example/fido2)
target_compile_options(test_ctap PRIVATE -Wall -Wextra)
add_test(NAME test_ctap COMMAND $<TARGET_FILE:test_ctap>)
