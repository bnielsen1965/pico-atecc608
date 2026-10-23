# Bench console example (example/console): probe/diagnostic commands over
# the serial console (pico-command-line), and — as of Phase 4B — the
# provisioning command set (prov status/randtest/iokey/config/lock).
# Proof of concept for the module; not part of the library.
add_executable(pico-atecc608
    main.c
)

# pico-littlefs — Pico-side persistence for /io_key.bin (and later
# /vault.db, /fido2.db). It is a sibling project of this repo
# (~/Projects/pico-littlefs — three levels up from example/console),
# not a submodule; the bare-metal default layout (FS at flash 0x80000,
# 384 x 4 KB) needs no override on this 4 MB app.
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../pico-littlefs
                 ${CMAKE_CURRENT_BINARY_DIR}/pico-littlefs)

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
