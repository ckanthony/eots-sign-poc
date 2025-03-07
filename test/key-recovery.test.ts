import { createHash } from 'crypto';
import { signEOTS } from '../src/lib/eots';
import { recoverPrivateKey } from '../src/lib/key-recovery';

describe('Key Recovery Tests', () => {
  // Test data
  const privateKey = Buffer.from(
    "914350c04b3189b493d350565909350cedf1ea1f849de3a70957ba9447c2a19a",
    "hex"
  );
  const reusedNonce = Buffer.from(
    "800ce414c9d98a89f8978bdf7cdb2706125eefefd743330c68c695c180e4d45b",
    "hex"
  );

  describe('recoverPrivateKey', () => {
    it('should recover private key when nonce is reused', () => {
      // Create two different messages
      const message1 = "First test message";
      const message2 = "Second test message";
      
      // Hash the messages
      const msg1Hash = createHash("sha256").update(message1).digest('hex');
      const msg2Hash = createHash("sha256").update(message2).digest('hex');

      // Sign both messages with the same nonce
      const sig1 = signEOTS(privateKey, msg1Hash, reusedNonce);
      const sig2 = signEOTS(privateKey, msg2Hash, reusedNonce);

      // Attempt to recover the private key
      const recoveredKey = recoverPrivateKey(
        sig1.s,
        sig2.s,
        msg1Hash,
        msg2Hash,
        sig1.publicKey,
        sig1.publicNonce
      );

      expect(recoveredKey).toBe(privateKey.toString('hex'));
    });

    it('should throw error for invalid hex inputs', () => {
      expect(() => recoverPrivateKey(
        'invalid',
        'f'.repeat(64),
        'f'.repeat(64),
        'f'.repeat(64),
        'f'.repeat(64),
        'f'.repeat(64)
      )).toThrow('All inputs must be 32-byte hex strings');
    });

    it('should throw error when challenges are equal', () => {
      // Sign the same message twice with same nonce
      const message = "Same message";
      const msgHash = createHash("sha256").update(message).digest('hex');
      
      const sig1 = signEOTS(privateKey, msgHash, reusedNonce);
      const sig2 = signEOTS(privateKey, msgHash, reusedNonce);

      expect(() => recoverPrivateKey(
        sig1.s,
        sig2.s,
        msgHash,
        msgHash,
        sig1.publicKey,
        sig1.publicNonce
      )).toThrow('Cannot recover key: challenges are equal');
    });

    it('should recover key for different message formats', () => {
      // Test with raw message and hash
      const rawMessage1 = "First message";
      const rawMessage2 = "Second message";
      const hash2 = createHash("sha256").update(rawMessage2).digest('hex');

      const sig1 = signEOTS(privateKey, rawMessage1, reusedNonce);
      const sig2 = signEOTS(privateKey, hash2, reusedNonce);

      const msg1Hash = createHash("sha256").update(rawMessage1).digest('hex');

      const recoveredKey = recoverPrivateKey(
        sig1.s,
        sig2.s,
        msg1Hash,
        hash2,
        sig1.publicKey,
        sig1.publicNonce
      );

      expect(recoveredKey).toBe(privateKey.toString('hex'));
    });
  });
}); 