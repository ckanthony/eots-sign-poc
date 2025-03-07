import { randomBytes } from 'crypto';
import { signEOTS, verifyEOTSSignature } from '../src/lib/eots';

describe('EOTS Signature Tests', () => {
  // Test data
  const privateKey = Buffer.from(
    "914350c04b3189b493d350565909350cedf1ea1f849de3a70957ba9447c2a19a",
    "hex"
  );
  const message = "Test message";
  const predefinedNonce = Buffer.from(
    "800ce414c9d98a89f8978bdf7cdb2706125eefefd743330c68c695c180e4d45b",
    "hex"
  );

  describe('signEOTS', () => {
    it('should generate valid signature with auto-generated nonce', () => {
      const signature = signEOTS(privateKey, message);
      
      expect(signature).toHaveProperty('publicKey');
      expect(signature).toHaveProperty('publicNonce');
      expect(signature).toHaveProperty('s');
      expect(signature.publicKey).toMatch(/^[0-9a-f]{64}$/i);
      expect(signature.publicNonce).toMatch(/^[0-9a-f]{64}$/i);
      expect(signature.s).toMatch(/^[0-9a-f]{64}$/i);
    });

    it('should generate valid signature with provided nonce', () => {
      const signature = signEOTS(privateKey, message, predefinedNonce);
      
      expect(signature).toHaveProperty('publicKey');
      expect(signature).toHaveProperty('publicNonce');
      expect(signature).toHaveProperty('s');
    });

    it('should throw error for invalid private key length', () => {
      const invalidKey = Buffer.from("deadbeef", "hex"); // Too short
      expect(() => signEOTS(invalidKey, message)).toThrow('Private key must be 32 bytes');
    });

    it('should throw error for invalid nonce length', () => {
      const invalidNonce = Buffer.from("deadbeef", "hex"); // Too short
      expect(() => signEOTS(privateKey, message, invalidNonce)).toThrow('Nonce must be 32 bytes');
    });

    it('should accept both string messages and hex hashes', () => {
      const stringMessage = "Test message";
      const hexHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

      const sig1 = signEOTS(privateKey, stringMessage);
      const sig2 = signEOTS(privateKey, hexHash);

      expect(sig1).toHaveProperty('publicKey');
      expect(sig2).toHaveProperty('publicKey');
    });
  });

  describe('verifyEOTSSignature', () => {
    it('should verify valid signature', () => {
      const signature = signEOTS(privateKey, message);
      const isValid = verifyEOTSSignature(
        signature.publicKey,
        signature.publicNonce,
        message,
        signature.s
      );
      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const signature = signEOTS(privateKey, message);
      const tamperedS = "f".repeat(64); // Invalid s value
      const isValid = verifyEOTSSignature(
        signature.publicKey,
        signature.publicNonce,
        message,
        tamperedS
      );
      expect(isValid).toBe(false);
    });

    it('should reject invalid public key format', () => {
      const signature = signEOTS(privateKey, message);
      expect(() => verifyEOTSSignature(
        "invalid",
        signature.publicNonce,
        message,
        signature.s
      )).toThrow('Invalid public key format');
    });

    it('should reject invalid public nonce format', () => {
      const signature = signEOTS(privateKey, message);
      expect(() => verifyEOTSSignature(
        signature.publicKey,
        "invalid",
        message,
        signature.s
      )).toThrow('Invalid public nonce format');
    });

    it('should reject invalid signature format', () => {
      const signature = signEOTS(privateKey, message);
      expect(() => verifyEOTSSignature(
        signature.publicKey,
        signature.publicNonce,
        message,
        "invalid"
      )).toThrow('Invalid signature format');
    });
  });

  describe('Deterministic Tests', () => {
    it('should produce consistent results with same inputs', () => {
      const msg = "Test deterministic message";
      const sig1 = signEOTS(privateKey, msg, predefinedNonce);
      const sig2 = signEOTS(privateKey, msg, predefinedNonce);

      expect(sig1.publicKey).toBe(sig2.publicKey);
      expect(sig1.publicNonce).toBe(sig2.publicNonce);
      expect(sig1.s).toBe(sig2.s);
    });
  });
}); 