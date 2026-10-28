# Examples — proof-of-concept applications built on the atecc608 module.
#
# These are NOT part of the library (include/ + src/ + tests/ are the
# product). Each example is a discrete application with its own
# top-level startup contract: check whether the chip is already
# provisioned, and if not, provision it (via the module's guarded
# provisioning API) before the application logic runs. The shared base
# for that contract lives in common/.
#
#   console/   bench console: probe/diag + provisioning command set
#   vault/     PIN-gated password store demo (ATECC608 as KDF master)
#   fido2/     FIDO2 (CTAP2) passkey authenticator (pure-HID USB key)
#
# See example/README.md for the contract and the agreed slot layout.

# Console/CLI framework used by the examples only (submodule checked out
# here, inside example/; the library itself has no dependency on it).
add_subdirectory(pico-command-line)

# The vault's `add <name> <pin> <password>` line carries three long tokens
# (16 + 24 + 40 chars plus separators), which overruns the framework's
# default 80-byte line buffer. pico-command-line is an INTERFACE library
# whose sources compile into each consuming app, so the define must be
# INTERFACE to reach both apps; the console just gets a longer line buffer.
target_compile_definitions(pico-command-line INTERFACE COMMAND_LINE_LEN=128)

# pico-littlefs — Pico-side persistence (submodule in example/; used by
# the examples only, the library does not depend on it). Added ONCE at
# this level rather than per app: CMake target names are unique across
# the whole build, so two apps cannot each add_subdirectory() it. The
# bare-metal default layout (FS at flash 0x80000, 384 x 4 KB) needs no
# override on this 4 MB app.
add_subdirectory(pico-littlefs)

add_subdirectory(console)
add_subdirectory(vault)
add_subdirectory(fido2)
