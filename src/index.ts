// Core EOTS functionality
export { signEOTS, verifyEOTSSignature, type EOTSSignature } from './lib/eots';

// Key recovery demonstration (shows why nonce reuse is dangerous)
export { recoverPrivateKey } from './lib/key-recovery'; 