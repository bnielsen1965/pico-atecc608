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
#   (future)   password-store/  fido2/  ...  one discrete app each
#
# See example/README.md for the contract and the agreed slot layout.

# Console/CLI framework used by the examples only (submodule at the repo
# root; the library itself has no dependency on it).
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../pico-command-line
                 ${CMAKE_CURRENT_BINARY_DIR}/pico-command-line)

add_subdirectory(console)
