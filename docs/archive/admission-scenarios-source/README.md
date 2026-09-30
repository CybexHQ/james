# Inactive admission scenario source archive

These files preserve the exact uncommitted source from the historical
`scenario-source` worktree, based on James commit `54f3c664a9377d017f0693e8fdb97ac96ba7282d`.
They were archived on 2026-09-30 from the preserved checkout at
`var/james-nixos/scenario-source`; the original worktree remains unchanged.
The `.py.txt` extension keeps both files outside executable modules and test discovery.
No release or qualification workflow loads this archive.

| Original path | Archived file | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `nixos-appliance/qualification/admission_scenarios.py` | `admission_scenarios.py.txt` | 14714 | `aa075f653cdd2be8eae8d4fb51e248cb4b89b4bd01331232bc55b163e2f7282b` |
| `tools/tests/test_admission_scenarios.py` | `test_admission_scenarios.py.txt` | 13937 | `85b55d8adcdcea617cbf645425bf43b13d0f1a559b42ae3224e82912b92dd81e` |

The experiment contains pure Q07 schedule/hold/deferral assertions and Q15
historical Ubuntu V2 reinstall/cancellation assertions, with synthetic unit-test
observations. It uses retired `james_reported_at`, `waiting` and
`maintenance_window` projection names and the historical
`cybex.james.appliance-release.v2` descriptor. It is not compatible with the
current Nest qualification API without a separate reviewed adaptation.

Current Q07 execution and tests live in
`nixos-appliance/qualification/schedule_admission.py` and
`tools/tests/test_nixos_schedule_qualification.py`. That harness supersedes the
experiment's intended schedule, maintenance lease, waiting-window and exact
Update now coverage, using real API operations and owned cleanup. Ubuntu runtime
qualification is retired; historical V2 descriptors remain ancestry evidence.

The archived tests do not establish genuine report ingestion, database
transaction atomicity, browser behavior, active-build race freedom, disk-pressure
safety, subsequent activation, or release acceptance. This archive commits the
unfinished work for preservation only. It changes no runtime, tests, admission
policy, or release gate. Source review found no credentials, private key material,
configuration, or runtime evidence; test identities and observations are synthetic.
