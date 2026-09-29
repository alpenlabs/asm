# Baseline manifest vectors

Generated using the unmodified manifest codec and locked dependencies from ASM
`45a1fa2f52289b483dd9767b4ec9c80545d5789b` (`v0.3.0-rc.2`).
Each manifest has height 100, block ID bytes `11` repeated 32 times, witness root
bytes `22` repeated 32 times, and 0, 1, 2 or 1,024 logs. Log i contains
`[i modulo 256, 2, 3]`. Expected roots are literal values in `manifest.rs`.

These are codec/commitment fixtures, not historical mainnet transactions or proof
qualification. The 1,024 limit is consensus-visible even for an empty list.
