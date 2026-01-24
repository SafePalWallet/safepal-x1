## Summary

Following a deep dive into the available SafePal X1 firmware source code and a comparison with the upgrade.bin binary (version X1_R31), I have identified several critical areas where the device's claims of "open source" and "security" conflict with the actual implementation. The firmware relies on obfuscated headers and hardcoded cryptographic keys, which significantly hinders independent auditability.

## Technical Findings

1. Opaque Firmware Structure & Header Obfuscation
While the header identifier SEFW is visible in the binary (SHA256:32a8032f2cf91d2a8a7ae013ec6d1813b8d05b05e2a0b59ac681e428186f78f0), the structure does not fully align with the provided FILE_INFO_ST definition in update.h.

CRC Mismatch: Standard CRC32 checks against the header fail, suggesting either a modified structure in production or an additional layer of obfuscation.

High Entropy: The payload (starting at 0x38 or 0x200) exhibits an entropy of 7.9998, confirming strong encryption (likely AES) that prevents static analysis without the keys stored in the Secure Element (SE).

2. Hardcoded Cryptographic Keys
The source code reveals the use of static, hardcoded "salt" values and keys for sensitive operations:

Activation Encryption: The active_decode_info function uses a hardcoded seckey. This key is a simple sequence (0x01, 0x23, 0x45...) and is used to decrypt device activation data.

Private Data Derivation: The AES key used to encrypt NVM data (like mnemonic entropy) is derived using gAESKeyMark. This salt is also hardcoded.

Derivation Formula: Key = SHA256(gAESKeyMark + PRODUCT_TYPE_VALUE + CPUID).

Risk: While the key is tied to the unique CPUID, the algorithm's reliance on hardcoded salts in the open-source layer reduces the security margin.

3. Reliance on Opaque Secure Element (SE) Commands
Most critical cryptographic operations (signing, key generation) are offloaded to the SE via sec_sapi_command.

The secure_api.c file acts merely as a wrapper for these commands.

The actual logic inside the SE remains a "black box," making it impossible to verify if the private keys are handled securely or if backdoors exist within the SE-side firmware.

4. Hardware Transparency Issues (Validated by Community Teardowns)
Independent teardowns of the X1 confirm:

Re-marked MCU: The main processor's surface is sanded and re-labeled with "SafePal X1," hiding its true origin.

USB Analog Switch: The inclusion of a UM7222 switch to physically disconnect the USB PHY from the MCU confirms a design that prioritizes "security through obscurity".

## Conclusion

The SafePal X1 is not "fully transparent." While the App-level code is available, the core security relies on:

Obfuscated hardware (Sanded MCU).

Opaque firmware (Binary blobs/SE commands).

Weakened crypto-implementations (Hardcoded salts/keys).

Suggested Next Steps for the Community
Develop a tool to brute-force the ST_CRC32 window to identify the exact production header format.

Intercept BLE traffic during activation to test the vulnerability of the hardcoded seckey.

Probe the UART/SWD pads on the PCB to extract the CPUID and test the NVM decryption logic.
