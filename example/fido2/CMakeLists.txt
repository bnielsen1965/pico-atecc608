# FIDO2 (CTAP2) passkey authenticator example (example/fido2): a pure-HID
# USB security key (2E8A:000B) backed by the ATECC608's on-chip ECC keys.
# No CDC — the USB interface is the FIDO HID interface only (flash via
# BOOTSEL UF2); debug output on UART0 (GPIO 0 TX / GPIO 1 RX).
add_executable(pico-atecc608-fido2
    main.c
    fido_hid.c
    fido_ctaphid.c
    fido_ctap.c
    fido_cred.c
    fido_cose.c
    fido_cbor.c
    fido_sha256.c
)

# tusb_config.h (this directory) must be reachable as a bare include from
# every TU that pulls in tusb.h.
target_include_directories(pico-atecc608-fido2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# tinyusb_device is the marked wrapper of tinyusb_device_unmarked in
# this pico-sdk fork (src/rp2_common/tinyusb); the marked target is what
# a standalone app links.
target_link_libraries(pico-atecc608-fido2
    atecc608::atecc608
    tinyusb_device
    pico_unique_id   # 8-byte unique ID -> USB serial string
    pico-littlefs    # credential DB (/f2_<slot>), same volume as console/vault
    pico_multicore   # core 1 runs the tight USB task (makeCredential delivery fix)
)

# The CTAP sync counter backend: littlefs /f2_cnt (default — survives
# reflashes and is zeroed by RESET / console 'wipe') or the chip's
# hardware-monotonic Counter 0 (FIDO2_COUNTER_CHIP=ON — never
# resettable; use it when the counter must survive a littlefs wipe).
option(FIDO2_COUNTER_CHIP "Use the ATECC608's Counter 0 for the CTAP sync counter" OFF)
if (FIDO2_COUNTER_CHIP)
    target_compile_definitions(pico-atecc608-fido2 PRIVATE FIDO2_COUNTER_CHIP)
endif ()

# Debug console on UART0 only — the USB interface is the HID key, so no
# stdio over USB (pico_enable_stdio_usb would clash with our own HID
# descriptor and add a CDC interface the FIDO layout does not have).
pico_enable_stdio_uart(pico-atecc608-fido2 1)

# Produce .uf2, .bin, .hex, .map, and disassembly alongside the ELF.
pico_add_extra_outputs(pico-atecc608-fido2)
