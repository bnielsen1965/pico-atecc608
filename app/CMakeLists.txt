# Demo / diagnostic console app.
#
# Phase 2: drives read-only operations through cryptoauthlib (atcab_*)
# initialized via the module's atecc608_init(). By Phase 6 it exercises the
# module's public atecc608_* API.
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
