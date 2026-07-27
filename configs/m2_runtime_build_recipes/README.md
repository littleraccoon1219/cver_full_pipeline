# M2 runtime build recipes

Runtime builds are disabled by default. A recipe is a JSON document containing argument-array commands, an approval record and a bounded timeout. The runner does not invoke a shell. Every command executable must be in `SafeCommandRunner.ALLOWED_NAMES`.

A recipe must remain `"approved": false` until it has been reviewed against the exact Kata tag or commit. M2 never writes to `/opt/kata`; build outputs stay below `data/m2/runtime-assets/<version>/build/` and must be registered separately.
