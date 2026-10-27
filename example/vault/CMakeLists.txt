# Vault example (example/vault): PIN-gated password store demo — the
# ATECC608 as KDF master (slot 7; the key never leaves the chip) and the
# Pico as the bulk cipher (software AES-256-GCM, host-verified in
# tests/test_vault_gcm). Proof of concept for the module; not part of the
# library. See example/README.md for the startup contract and caveats.
add_executable(pico-atecc608-vault
    main.c
    vault_gcm.c
)

# pico-littlefs — added once at the example/ level (CMake target names
# are build-wide unique, so it cannot be added per app); both apps link
# the same static library. It shares the volume (flash 0x80000) with the
# console app: /io_key.bin (written by the console) and the /v_<name>
# entry files survive console <-> vault reflashes.

# No pico_rand: all randomness comes from the chip (salt/nonce), which is
# the point of the demo.
target_link_libraries(pico-atecc608-vault
    atecc608::atecc608
    pico-command-line
    pico-littlefs
    pico_multicore
)

# The shared I/O key file contract (example/common/iokey_file.h).
target_include_directories(pico-atecc608-vault PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

# Console output over both USB serial (no extra wiring) and UART0 on GPIO 0
# (TX) / GPIO 1 (RX) for a USB-serial adapter.
pico_enable_stdio_usb(pico-atecc608-vault 1)
pico_enable_stdio_uart(pico-atecc608-vault 1)

# Produce .uf2, .bin, .hex, .map, and disassembly alongside the ELF.
pico_add_extra_outputs(pico-atecc608-vault)
