# Provenance and License Notes

This project was developed with assistance from a large language model under human direction. A human operator defined the scope, reviewed the outputs, selected the final changes, and validated the behavior.

## Upstream Sources Reviewed

- `PXEThief`
  Source checked: local `PXEThief/LICENSE` and upstream repository metadata.
  Result: GPL-3.0.

- `cred1py`
  Source checked: local `cred1py/` snapshot and upstream repository metadata.
  Result: no license file was found locally, and upstream GitHub metadata did not report a license as of March 7, 2026.

## Practical Implications

- Code or logic derived from `PXEThief` should retain attribution and comply with GPL-3.0 obligations.
- `cred1py` licensing is unresolved from the materials reviewed here. Attribution alone does not create redistribution rights.
- Public redistribution of `cred1py`-derived portions may require explicit permission from SpecterOps or replacement of those portions with independently authored code.

## Additional Upstream Sources Reviewed (2026-08-20)

- `pxethiefup` (https://github.com/evildaemond/pxethiefup)
  Source checked: cloned upstream repository, no LICENSE file present, but
  `media_variable_file_cryptography.py` carries the same PXEThief GPL-3.0
  header (Copyright (C) 2022 Christopher Panayi, MWR CyberSec). Treated as
  GPL-3.0-derived, same as PXEThief.
  Result: weak/default password auto-try and hashcat mode wiring re-implemented
  in `lib/sccm.py` / `pxehacker.py` (not copied verbatim).

- `PXEThief` (blurbdust fork, https://github.com/blurbdust/PXEThief)
  Source checked: cloned upstream repository, GPL-3.0 LICENSE file present.
  Result: legacy CALG_3DES cryptokey-derivation branch re-implemented in
  `lib/sccm.py` (not copied verbatim, unverified against a live capture).

Neither review found a licensing complication beyond what's already noted
above for `PXEThief` — both forks derive from and carry GPL-3.0 attribution.
No files were copied wholesale from either fork; logic was re-implemented
per the existing `lib/` conventions and attributed in code comments.

## Current Repository Status

- Attribution to `PXEThief`, `cred1py`, and other upstream projects is present in the code and README.
- The repository contains material described as merged, ported, or enhanced from those upstream projects.
- Because `cred1py` does not appear to publish a license in the reviewed materials, this repository should not be treated as clearly redistributable in its current form without further permission review.

This file is an engineering note, not legal advice.
