cmake_minimum_required(VERSION 3.13)

# Board: Raspberry Pi Pico 2 (RP2350). Must be set before including the SDK,
# since the SDK reads it at configure time.
set(PICO_BOARD pico2)

# Core: defaults to the Cortex-M33 cores (rp2350-arm-s). The RP2350's two
# cores can each run either Cortex-M33 or Hazard3 RISC-V, and pico_multicore
# supports both, so this program builds and runs on either platform:
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

# C11 matters: newer GCCs default to C23, where an empty
# function prototype `()` means `(void)` and conflicts with the
# pico-command-line declarations.
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

pico_sdk_init()

# Command line interface (INTERFACE library providing the `pico-command-line` target)
add_subdirectory(pico-command-line)

add_executable(pico-atecc608
    src/main.c
    src/atecc608.c
)

target_include_directories(pico-atecc608 PRIVATE src)

target_link_libraries(pico-atecc608
    pico_stdlib
    pico_multicore
    pico-command-line
    hardware_i2c
)

# Console output over both USB serial (no extra wiring) and
# UART0 on GPIO 0 (TX) / GPIO 1 (RX) for a USB-serial adapter.
pico_enable_stdio_usb(pico-atecc608 1)
pico_enable_stdio_uart(pico-atecc608 1)

# Produce .uf2, .bin, .hex, .map, and disassembly alongside the ELF.
pico_add_extra_outputs(pico-atecc608)
