# FIDO2 debug tools

Home for host-side tool scripts that help debug the FIDO2 (CTAP2) example.
Put **new** FIDO2 tool scripts here so they survive across sessions (they are
committed with the repo, unlike `/tmp` scratch).

Convention: any new tool script created while
debugging the FIDO2 application goes in this directory.

## Existing bench harness (lives in `../bench/`, not here)

- `../bench/fido_probe.py` — CTAPHID probe: INIT / PING / WINK / GET_INFO
  85-byte KAT. Must FULL PASS at the start of every bench session.
- `../bench/fido_watch.py` — live CTAPHID monitor (decodes the wire, including
  the 0x3B keep-alive with status at offset 7).
- `../bench/fido_desc_probe.c` / `fido_desc_probe` — USB descriptor probe.

## Decode note

`tshark` is the ground-truth decoder for the usbmon captures
(`tshark -r <file> -V`, then `-Y frame.number==N -x` for full hex). A
standalone Python framer is unreliable for this usbmon format.

## Regenerating the getAssertion KAT fixtures

`tests/test_ctap.c` pins the getAssertion / GET_NEXT_ASSERTION responses as
byte arrays. If you change those test vectors (rp id, counters, credential
ids, …), regenerate the fixtures offline — independently of the C code — and
splice them back in. Run both from this directory:

```sh
python3 gen_ga_kat.py     # writes ga_kat_fixtures.c (gitignored) here
python3 splice_ga_kat.py  # splices it into tests/test_ctap.c
```

`gen_ga_kat.py` first sanity-checks that its offline method reproduces the
original pinned signature, so a drift in the method is caught before it
corrupts the test. The transient `ga_kat_fixtures.c` is not committed.
