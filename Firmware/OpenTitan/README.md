# OpenTitan mailbox firmware

The supplied firmware adapted for Deeploy L2/L1 double buffering is
`firmware_async.c`, which includes `deeploy_ot_service.inc`.

See [integration instructions](../../docs/OpenTitanDoubleBuffering.md) for the
shared 48-byte ABI, required PULP runtime changes, hardware assumptions and tests.
Do not build `firmware_original.c.txt`; it is the original attachment for reference.
