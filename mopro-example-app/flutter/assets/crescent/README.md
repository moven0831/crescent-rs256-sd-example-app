# Crescent RS256-SD Assets

This directory contains real cryptographic artifacts for the Crescent RS256-SD selective disclosure system.

## Directory Structure

```
crescent/
└── rs256-sd/
    ├── token.jwt              # Real RSA-256 signed JWT token
    ├── issuer.pub            # RSA public key for JWT verification
    ├── config.json           # Schema configuration for claims
    ├── proof_spec.json       # Selective disclosure specification
    ├── main.wasm            # Compiled Circom circuit (7.7MB)
    ├── groth16_vk.bin       # Groth16 verification key
    └── range_vk.bin         # Range proof verification key
```

## File Descriptions

### Credential Files
- **token.jwt**: A real Microsoft Azure AD style JWT token with RSA-256 signature
- **issuer.pub**: The RSA public key used to verify the JWT signature
- **config.json**: Defines which JWT claims are available for selective disclosure
- **proof_spec.json**: Specifies which claims to reveal in this test scenario

### Circuit Files
- **main.wasm**: WebAssembly compiled Circom circuit for RS256-SD proofs
- **groth16_vk.bin**: Verification key for the main Groth16 proof system
- **range_vk.bin**: Verification key for range proofs (used for expiration checks)

## Usage in Flutter App

These assets are loaded natively by the iOS/Android platform code and used by the Crescent RS256-SD proving system. The Flutter app provides a UI for:

1. **Prove**: Generate client state from the JWT token
2. **Show**: Create selective disclosure proof based on proof_spec.json
3. **Verify**: Validate the presentation and show revealed claims

## Security Note

These are test artifacts suitable for development and demonstration. For production use, you would:
- Use real JWT tokens from your authentication system
- Load proper issuer certificates from trusted sources
- Generate fresh cryptographic parameters via trusted setup

## Asset Sizes

- Total size: ~8MB (suitable for mobile app distribution)
- Largest file: main.wasm (7.7MB)
- Note: Large proving parameters (680MB) are excluded for mobile efficiency