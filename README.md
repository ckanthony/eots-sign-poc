# EOTS Sign PoC

A Proof of Concept implementation of an Ephemeral One-Time Signature (EOTS) scheme using Schnorr signatures, designed to prevent claim reuse by enforcing single-use signatures through public nonce exposure.

## Overview

This project demonstrates how EOTS can protect against signature/claim reuse by making it impossible for a signer to reuse their signature without exposing their private key:

1. **EOTS Implementation**: A secure Schnorr signing procedure that deliberately exposes the public nonce, making it publicly visible. Each signature contains:
   - `publicKey`: the x‑coordinate of the signer's public key (32‑byte hex, with even y assumed)
   - `publicNonce`: the x‑coordinate of the ephemeral nonce point R (32‑byte hex, with even y)
   - `s`: the signature scalar (32‑byte hex)

2. **Protection Mechanism**: By making the nonce public, any attempt to reuse it for a second claim would expose the signer's private key. This creates a strong deterrent against signature reuse, effectively making each signature single-use only.

## Installation

```bash
npm install
```

## Security Mechanism Demonstration

To understand how EOTS protects against claim reuse, run:

```bash
yarn demo:vulnerability
```

This demonstrates:
1. How a signature is bound to a single claim through its public nonce
2. Why attempting to reuse the signature for a different claim would expose the signer's private key
3. The mathematical proof that makes this protection possible

### Understanding the Protection

The security relies on the fact that if someone tries to reuse a nonce to sign two different claims, they create two equations:
```
s1 = a + e1*d  (mod n)
s2 = a + e2*d  (mod n)
```
where:
- `s1`, `s2` are the signature scalars
- `a` is the exposed nonce
- `e1`, `e2` are the challenge values
- `d` is the private key
- `n` is the curve order

Any attempt to sign a second claim would allow others to solve:
```
s1 - s2 = d * (e1 - e2)  (mod n)
```

This would reveal the private key `d`, making it financially catastrophic to attempt claim reuse.

## Usage

### Basic Example

```typescript
import { signEOTS, verifyEOTSSignature } from 'eots-sign-poc';

const claim = "I am selling this asset for 1 BTC";
const privateKey = Buffer.from("your-private-key-hex", "hex");
const nonce = Buffer.from("your-nonce-hex", "hex");

// Sign claim - this will expose the public nonce
const signature = signEOTS(privateKey, claim, nonce);

// Anyone can verify the claim
const isValid = verifyEOTSSignature(
  signature.publicKey,
  signature.publicNonce,
  claim,
  signature.s
);
```

### Running Examples

```bash
npm run demo:vulnerability  # Claim reuse protection demo
```

## Development

### Build
```bash
npm run build
```

### Test
```bash
npm test
```

### Lint
```bash
npm run lint
```

### Format Code
```bash
npm run format
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
