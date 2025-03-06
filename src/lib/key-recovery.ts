import { createHash } from "crypto";

// secp256k1 curve order (n)
const CURVE_N: bigint = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

// BIP340 tag for challenge computation
const BIP340_TAG = Buffer.from(
  "7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c",
  "hex"
);

/**
 * Computes the challenge scalar e given the public nonce, public key, and message.
 * 
 * @param publicNonceHex - The x-coordinate of the public nonce (hex)
 * @param publicKeyHex - The x-coordinate of the public key (hex)
 * @param messageHex - The message hash in hex
 * @returns The challenge value as a bigint
 */
function calculateChallenge(
  publicNonceHex: string,
  publicKeyHex: string,
  messageHex: string
): bigint {
  const challengeData = Buffer.concat([
    BIP340_TAG,
    BIP340_TAG,
    Buffer.from(publicNonceHex, "hex"),
    Buffer.from(publicKeyHex, "hex"),
    Buffer.from(messageHex, "hex"),
  ]);
  const eHash = createHash("sha256").update(challengeData).digest();
  return BigInt("0x" + eHash.toString("hex"));
}

/**
 * Computes the modular inverse of a modulo n using the Extended Euclidean Algorithm.
 * 
 * @param a - The number to find the inverse of
 * @param n - The modulus
 * @returns The modular inverse of a mod n
 * @throws Error if the inverse does not exist
 */
function modInverse(a: bigint, n: bigint): bigint {
  let t = 0n,
    newT = 1n;
  let r = n,
    newR = a % n;

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r > 1n) throw new Error("a is not invertible modulo n");
  if (t < 0n) t += n;
  return t;
}

/**
 * Recovers the signing private key given two signatures that reused the same nonce.
 * This demonstrates why nonce reuse is catastrophic for security.
 * 
 * @param s1Hex - Signature scalar s for message 1 (hex)
 * @param s2Hex - Signature scalar s for message 2 (hex)
 * @param msg1Hex - Message hash for signature 1 (hex)
 * @param msg2Hex - Message hash for signature 2 (hex)
 * @param pubKeyHex - Public key x-coordinate (hex)
 * @param pubNonceHex - Public nonce x-coordinate (hex)
 * @returns The recovered private key in hex
 * @throws Error if inputs are invalid or recovery fails
 */
export function recoverPrivateKey(
  s1Hex: string,
  s2Hex: string,
  msg1Hex: string,
  msg2Hex: string,
  pubKeyHex: string,
  pubNonceHex: string
): string {
  // Input validation
  const hexPattern = /^[0-9a-f]{64}$/i;
  if (![s1Hex, s2Hex, msg1Hex, msg2Hex, pubKeyHex, pubNonceHex].every(h => 
    hexPattern.test(h))) {
    throw new Error('All inputs must be 32-byte hex strings');
  }

  // Calculate the challenges for both messages
  const e1 = calculateChallenge(pubNonceHex, pubKeyHex, msg1Hex);
  const e2 = calculateChallenge(pubNonceHex, pubKeyHex, msg2Hex);

  const s1 = BigInt("0x" + s1Hex);
  const s2 = BigInt("0x" + s2Hex);

  // The two signature equations (modulo n) are:
  //   s1 = a + e1*d
  //   s2 = a + e2*d
  // Subtracting the second from the first gives:
  //   s1 - s2 = d * (e1 - e2)
  // Solve for d:
  const numerator = (s1 - s2 + CURVE_N) % CURVE_N;
  const denominator = (e1 - e2 + CURVE_N) % CURVE_N;

  if (denominator === 0n) {
    throw new Error('Cannot recover key: challenges are equal');
  }

  const invDenom = modInverse(denominator, CURVE_N);
  const d = (numerator * invDenom) % CURVE_N;
  return d.toString(16).padStart(64, "0");
} 