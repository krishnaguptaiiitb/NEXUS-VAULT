/* global globalThis */

const HYBRID_ALGORITHM = "X25519-ML-KEM-768";
const ENVELOPE_VERSION = 2;
const ML_KEM_ALGORITHM = "ML-KEM-768";

const HKDF_INFO = new TextEncoder().encode(
  "NexusVault|envelope-v2|X25519-ML-KEM-768|AES-256-GCM"
);

const WRAPPING_AAD = new TextEncoder().encode(
  "NexusVault|envelope-v2|X25519-ML-KEM-768"
);

const encoder = new TextEncoder();

function ensureCryptoSupport() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is not available in this browser.");
  }

  if (
    typeof crypto.subtle.encapsulateBits !== "function" ||
    typeof crypto.subtle.decapsulateBits !== "function"
  ) {
    throw new Error(
      "This browser does not support ML-KEM-768. Use a compatible Chromium-based browser."
    );
  }
}

function toBase64(buffer) {
  const bytes =
    buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(binary);
}

function fromBase64(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("Invalid or missing Base64 value.");
  }

  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function toArrayBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return value;
  }

  if (ArrayBuffer.isView(value)) {
    return value.buffer.slice(
      value.byteOffset,
      value.byteOffset + value.byteLength
    );
  }

  throw new Error("Expected an ArrayBuffer or typed array.");
}

function concatenateSecrets(first, second) {
  const a = new Uint8Array(first);
  const b = new Uint8Array(second);

  const combined = new Uint8Array(a.length + b.length);

  combined.set(a, 0);
  combined.set(b, a.length);

  return combined;
}

function validateLength(value, expectedLength, fieldName) {
  if (value.length !== expectedLength) {
    throw new Error(
      `${fieldName} must be exactly ${expectedLength} bytes.`
    );
  }
}

async function deriveWrappingKey(x25519Secret, mlkemSecret, salt) {
  const combinedSecret = concatenateSecrets(
    x25519Secret,
    mlkemSecret
  );

  try {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      combinedSecret,
      "HKDF",
      false,
      ["deriveKey"]
    );

    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: HKDF_INFO
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["encrypt", "decrypt"]
    );
  } finally {
    combinedSecret.fill(0);
  }
}

/**
 * Wraps an existing 256-bit AES file key for a recipient.
 *
 * recipientPublicKeys:
 * {
 *   x25519PublicKey: Base64 raw X25519 public key,
 *   mlkem768PublicKey: Base64 ML-KEM-768 raw-public key
 * }
 */
export async function wrapFileKeyForRecipient(
  fileKey,
  recipientPublicKeys
) {
  ensureCryptoSupport();

  if (!recipientPublicKeys?.x25519PublicKey) {
    throw new Error("Recipient X25519 public key is missing.");
  }

  if (!recipientPublicKeys?.mlkem768PublicKey) {
    throw new Error("Recipient ML-KEM-768 public key is missing.");
  }

  const rawFileKey = new Uint8Array(toArrayBuffer(fileKey));
  validateLength(rawFileKey, 32, "AES-256 file key");

  const x25519PublicBytes = fromBase64(
    recipientPublicKeys.x25519PublicKey
  );

  const mlkemPublicBytes = fromBase64(
    recipientPublicKeys.mlkem768PublicKey
  );

  validateLength(x25519PublicBytes, 32, "X25519 public key");
  validateLength(mlkemPublicBytes, 1184, "ML-KEM-768 public key");

  // Import recipient X25519 public key.
  const recipientX25519PublicKey = await crypto.subtle.importKey(
    "raw",
    x25519PublicBytes,
    {
      name: "X25519"
    },
    false,
    []
  );

  // Generate an ephemeral X25519 key pair.
  const ephemeralKeyPair = await crypto.subtle.generateKey(
    {
      name: "X25519"
    },
    true,
    ["deriveBits"]
  );

  // Derive the X25519 shared secret.
  const x25519Secret = await crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: recipientX25519PublicKey
    },
    ephemeralKeyPair.privateKey,
    256
  );

  // Export the ephemeral public key for the recipient.
  const ephemeralPublicKey = await crypto.subtle.exportKey(
    "raw",
    ephemeralKeyPair.publicKey
  );

  // Import recipient ML-KEM-768 public key.
  const recipientMlkemPublicKey = await crypto.subtle.importKey(
    "raw-public",
    mlkemPublicBytes,
    {
      name: ML_KEM_ALGORITHM
    },
    false,
    ["encapsulateBits"]
  );

  // Encapsulate the ML-KEM shared secret.
  const mlkemResult = await crypto.subtle.encapsulateBits(
    {
      name: ML_KEM_ALGORITHM
    },
    recipientMlkemPublicKey
  );

  const mlkemSecret = mlkemResult.sharedKey;
  const mlkemCiphertext = mlkemResult.ciphertext;

  validateLength(
    new Uint8Array(mlkemSecret),
    32,
    "ML-KEM shared secret"
  );

  validateLength(
    new Uint8Array(mlkemCiphertext),
    1088,
    "ML-KEM ciphertext"
  );

  // Generate fresh salt and AES-GCM nonce.
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Derive the AES-256-GCM key from both KEM secrets.
  const wrappingKey = await deriveWrappingKey(
    x25519Secret,
    mlkemSecret,
    salt
  );

  // Encrypt the actual AES file key.
  const wrappedKey = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: WRAPPING_AAD,
      tagLength: 128
    },
    wrappingKey,
    rawFileKey
  );

  return {
    envelopeVersion: ENVELOPE_VERSION,
    keyAlgorithm: HYBRID_ALGORITHM,

    x25519EphemeralPublicKey: toBase64(ephemeralPublicKey),
    mlkemCiphertext: toBase64(mlkemCiphertext),

    hkdfSalt: toBase64(salt),
    wrappingNonce: toBase64(nonce),
    wrappedKey: toBase64(wrappedKey)
  };
}

/**
 * Unwraps a file key using the recipient's hybrid private keys.
 *
 * envelope: hybrid envelope returned by the backend.
 *
 * privateKeys:
 * {
 *   x25519PrivateKey: Base64 PKCS8 private key,
 *   mlkem768PrivateKey: Base64 raw-seed private key
 * }
 */
export async function unwrapFileKey(
  envelope,
  privateKeys
) {
  ensureCryptoSupport();

  if (!envelope || envelope.envelopeVersion !== ENVELOPE_VERSION) {
    throw new Error("Unsupported or invalid hybrid envelope version.");
  }

  if (envelope.keyAlgorithm !== HYBRID_ALGORITHM) {
    throw new Error("Unsupported envelope key algorithm.");
  }

  if (!privateKeys?.x25519PrivateKey) {
    throw new Error("X25519 private key is missing.");
  }

  if (!privateKeys?.mlkem768PrivateKey) {
    throw new Error("ML-KEM-768 private key is missing.");
  }

  const ephemeralPublicBytes = fromBase64(
    envelope.x25519EphemeralPublicKey
  );

  const mlkemCiphertext = fromBase64(
    envelope.mlkemCiphertext
  );

  const salt = fromBase64(envelope.hkdfSalt);
  const nonce = fromBase64(envelope.wrappingNonce);
  const wrappedKey = fromBase64(envelope.wrappedKey);

  validateLength(
    ephemeralPublicBytes,
    32,
    "Ephemeral X25519 public key"
  );

  validateLength(
    mlkemCiphertext,
    1088,
    "ML-KEM-768 ciphertext"
  );

  if (salt.length !== 32) {
    throw new Error("Invalid HKDF salt length.");
  }

  validateLength(nonce, 12, "AES-GCM wrapping nonce");
  validateLength(wrappedKey, 48, "Wrapped AES-256 file key");

  // Import recipient X25519 private key.
  const x25519PrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    fromBase64(privateKeys.x25519PrivateKey),
    {
      name: "X25519"
    },
    false,
    ["deriveBits"]
  );

  // Import ephemeral X25519 public key.
  const ephemeralX25519PublicKey = await crypto.subtle.importKey(
    "raw",
    ephemeralPublicBytes,
    {
      name: "X25519"
    },
    false,
    []
  );

  // Derive the same X25519 shared secret.
  const x25519Secret = await crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: ephemeralX25519PublicKey
    },
    x25519PrivateKey,
    256
  );

  // Import ML-KEM-768 private seed.
  const mlkemPrivateKey = await crypto.subtle.importKey(
    "raw-seed",
    fromBase64(privateKeys.mlkem768PrivateKey),
    {
      name: ML_KEM_ALGORITHM
    },
    false,
    ["decapsulateBits"]
  );

  // Recover the ML-KEM shared secret.
  const mlkemSecret = await crypto.subtle.decapsulateBits(
    {
      name: ML_KEM_ALGORITHM
    },
    mlkemPrivateKey,
    mlkemCiphertext
  );

  validateLength(
    new Uint8Array(mlkemSecret),
    32,
    "Recovered ML-KEM shared secret"
  );

  // Reconstruct the wrapping key.
  const wrappingKey = await deriveWrappingKey(
    x25519Secret,
    mlkemSecret,
    salt
  );

  // Authenticate and decrypt the wrapped file key.
  // Any incorrect key or modified envelope should fail authentication.
  const rawFileKey = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: WRAPPING_AAD,
      tagLength: 128
    },
    wrappingKey,
    wrappedKey
  );

  validateLength(
    new Uint8Array(rawFileKey),
    32,
    "Recovered AES-256 file key"
  );

  return rawFileKey;
}

export {
  HYBRID_ALGORITHM,
  ENVELOPE_VERSION,
  toBase64,
  fromBase64
};
