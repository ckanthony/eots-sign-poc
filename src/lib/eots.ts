import { randomBytes, createHash } from 'crypto';
import { ProjectivePoint as Point, CURVE } from '@noble/secp256k1';

// BIP340 tag for challenge computation
const BIP340_TAG = Buffer.from("7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c", "hex");

export interface EOTSSignature {
  publicKey: string;   // x-coordinate of public key (hex)
  publicNonce: string; // x-coordinate of public nonce R (hex)
  s: string;          // signature scalar (hex)
}

/**
 * Signs a message using the EOTS (Ephemeral One-Time Signature) scheme.
 * 
 * @param privateKey - A 32‑byte Uint8Array representing the private key
 * @param message - The message string to sign (will be hashed if not already)
 * @param choosenNonce - Optional predetermined nonce (32 bytes). If not provided, generates a random one
 * @returns An object containing the signature components
 * @throws Error if inputs are invalid
 */
export function signEOTS(
  privateKey: Uint8Array,
  message: string,
  choosenNonce?: Uint8Array
): EOTSSignature {
  // Input validation
  if (privateKey.length !== 32) {
    throw new Error('Private key must be 32 bytes');
  }
  if (choosenNonce && choosenNonce.length !== 32) {
    throw new Error('Nonce must be 32 bytes');
  }

  // Generate random nonce if not provided
  const nonce = choosenNonce || randomBytes(32);

  // Step 1: Compute public key with even y coordinate
  let P = Point.fromPrivateKey(privateKey);
  const d_original = BigInt("0x" + Buffer.from(privateKey).toString("hex"));
  
  // If P's y is odd, negate the private key
  if ((P.y & 1n) === 1n) {
    const d_neg = CURVE.n - d_original;
    const dNegHex = d_neg.toString(16).padStart(64, "0");
    privateKey = Uint8Array.from(Buffer.from(dNegHex, "hex"));
    P = Point.fromPrivateKey(privateKey);
  }
  const pubKeyHex = P.x.toString(16).padStart(64, "0");

  // Step 2: Generate nonce point R with even y coordinate
  let a = BigInt("0x" + nonce.toString("hex"));
  let R = Point.BASE.multiply(a);
  if ((R.y & 1n) === 1n) {
    a = CURVE.n - a;
    R = Point.BASE.multiply(a);
  }
  const rHex = R.x.toString(16).padStart(64, "0");

  // Step 3: Compute challenge e = SHA256(tag || tag || r || pubKey || message)
  const messageHash = typeof message === 'string' && message.length === 64 
    ? message  // assume it's already a hex hash if 64 chars
    : createHash("sha256").update(message).digest('hex');

  const challengeData = Buffer.concat([
    BIP340_TAG,
    BIP340_TAG,
    Buffer.from(rHex, "hex"),
    Buffer.from(pubKeyHex, "hex"),
    Buffer.from(messageHash, "hex"),
  ]);
  const eHash = createHash("sha256").update(challengeData).digest();
  const e = BigInt("0x" + eHash.toString("hex"));

  // Step 4: Compute signature scalar s = a + e * d mod n
  const d = BigInt("0x" + Buffer.from(privateKey).toString("hex"));
  const s = (a + e * d) % CURVE.n;
  const sHex = s.toString(16).padStart(64, "0");

  return { publicKey: pubKeyHex, publicNonce: rHex, s: sHex };
}

/**
 * Verifies an EOTS signature.
 * 
 * @param publicKeyHex - The x-coordinate of the public key (hex)
 * @param publicNonceHex - The x-coordinate of the public nonce (hex)
 * @param message - The original message or its hash
 * @param sHex - The signature scalar (hex)
 * @returns true if signature is valid, false otherwise
 * @throws Error if inputs are invalid
 */
export function verifyEOTSSignature(
  publicKeyHex: string,
  publicNonceHex: string,
  message: string,
  sHex: string
): boolean {
  // Input validation
  if (!/^[0-9a-f]{64}$/i.test(publicKeyHex)) {
    throw new Error('Invalid public key format');
  }
  if (!/^[0-9a-f]{64}$/i.test(publicNonceHex)) {
    throw new Error('Invalid public nonce format');
  }
  if (!/^[0-9a-f]{64}$/i.test(sHex)) {
    throw new Error('Invalid signature format');
  }

  // Convert message to hash if needed
  const messageHash = typeof message === 'string' && message.length === 64 
    ? message 
    : createHash("sha256").update(message).digest('hex');

  // Compute challenge e = SHA256(tag || tag || r || pubKey || message)
  const challengeData = Buffer.concat([
    BIP340_TAG,
    BIP340_TAG,
    Buffer.from(publicNonceHex, "hex"),
    Buffer.from(publicKeyHex, "hex"),
    Buffer.from(messageHash, "hex"),
  ]);
  const eHash = createHash("sha256").update(challengeData).digest();
  const e = BigInt("0x" + eHash.toString("hex"));

  // Convert signature scalar
  const s = BigInt("0x" + sHex);
  
  // Validate that s is within the valid range for secp256k1
  if (s >= CURVE.n || s <= 0n) {
    return false;
  }
  
  // Compute s·G
  const sG = Point.BASE.multiply(s);

  // Recover full public key and public nonce points (even y)
  const pubKeyCompressed = "02" + publicKeyHex;
  const P = Point.fromHex(pubKeyCompressed);
  const nonceCompressed = "02" + publicNonceHex;
  const R = Point.fromHex(nonceCompressed);

  // Verify s·G = R + e·P
  const expected = R.add(P.multiply(e));
  return sG.equals(expected);
} 