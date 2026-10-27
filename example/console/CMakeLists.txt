# Bench console example (example/console): probe/diagnostic commands over
# the serial console (pico-command-line), and — as of Phase 4B — the
# provisioning command set (prov status/randtest/iokey/config/lock).
# Proof of concept for the module; not part of the library.
add_executable(pico-atecc608
    main.c
)

# pico-littlefs — added once at the example/ level (CMake target names
# are build-wide unique, so it cannot be added per app); both apps link
# the same static library. It backs /io_key.bin here and the vault
# example's /v_<name> entry files.

target_link_libraries(pico-atecc608
    atecc608::atecc608
    pico-command-line
    pico-littlefs
    pico_rand
    pico_multicore
)

# The agreed 4B dev-config intent, shared with the host byte-plan tool so
# both always encode the same image (example/common/dev_config.h).
target_include_directories(pico-atecc608 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

# Console output over both USB serial (no extra wiring) and UART0 on GPIO 0
# (TX) / GPIO 1 (RX) for a USB-serial adapter.
pico_enable_stdio_usb(pico-atecc608 1)
pico_enable_stdio_uart(pico-atecc608 1)

# Produce .uf2, .bin, .hex, .map, and disassembly alongside the ELF.
pico_add_extra_outputs(pico-atecc608)
