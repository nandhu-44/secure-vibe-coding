# Embedded / firmware

- **No dynamic allocation after init** (or none at all). Use static pools with bounds. Check stack depth (`-fstack-usage`, MPU stack guard).
- Validate every byte from radios, buses (UART/SPI/I2C/CAN/USB), and OTA images: lengths, checksums, state.
- **Secure boot & signed OTA**: verify signatures (Ed25519/ECDSA P-256) over the full image before flashing, with anti-rollback version counters. Never accept unsigned updates. Use A/B partitions.
- **No hardcoded credentials or shared keys across devices.** Provision unique per-device keys in a secure element/TPM/TrustZone or protected flash. Disable debug (JTAG/SWD) in production via fuses/RDP levels.
- Use a hardware TRNG or a vetted DRBG for randomness. Never `rand()`.
- TLS: mbedTLS/wolfSSL with certificate verification enabled and a pinned CA. Time-source issues are not a reason to disable verification.
- Watchdogs, brown-out handling, and fail-safe defaults (actuators off) on errors.
- Integer widths: be explicit (`uint16_t`). Watch promotions and the `sizeof(int)` = 2 platforms.
- Follow MISRA C:2023 / CERT C where required. Run static analysis (cppcheck MISRA addon, CodeQL).
- Regulatory: the EU Cyber Resilience Act (Regulation (EU) 2024/2847) and ETSI EN 303 645 (consumer IoT) require no default passwords, vulnerability disclosure, and secure updates.
