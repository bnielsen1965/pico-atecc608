# Bench console example (example/console): probe/diagnostic commands over
# the serial console (pico-command-line), and — as of Phase 4B — the
# provisioning command set (prov status/randtest/iokey/config/lock).
# Proof of concept for the module; not part of the library.
add_executable(pico-atecc608
    main.c
)

target_link_libraries(pico-atecc608
    atecc608::atecc608
    pico-command-line
    pico_multicore
)

# Console output over both USB serial (no extra wiring) and UART0 on GPIO 0
# (TX) / GPIO 1 (RX) for a USB-serial adapter.
pico_enable_stdio_usb(pico-atecc608 1)
pico_enable_stdio_uart(pico-atecc608 1)

# Produce .uf2, .bin, .hex, .map, and disassembly alongside the ELF.
pico_add_extra_outputs(pico-atecc608)
