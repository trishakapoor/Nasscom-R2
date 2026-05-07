// lib/encryption.ts
// This file handles all encryption and decryption of sensitive data.
// It uses AES-256-GCM — the same encryption standard used by banks.

const ALGORITHM = "AES-GCM";
const KEY_LENGTH = 256;
const IV_LENGTH = 12;
const SALT = "captain-obvious-helpdesk-v1";

// Cache the key so we only derive it once per server start (better performance)
let cachedKey: CryptoKey | null = null;

/**
 * Reads ENCRYPTION_SECRET from .env.local and turns it into a usable crypto key.
 * This only runs once — after that it uses the cached version.
 */
async function getDerivedKey(): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;

  const secret = process.env.ENCRYPTION_SECRET;
  if (!secret) {
    throw new Error(
      "ENCRYPTION_SECRET is missing from .env.local! Please add it."
    );
  }

  const encoder = new TextEncoder();

  // Step 1: Import the raw secret string as key material
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  // Step 2: Derive a strong AES key using PBKDF2
  // 100,000 iterations makes it extremely hard to brute force
  cachedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: encoder.encode(SALT),
      iterations: 100_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );

  return cachedKey;
}

/**
 * ENCRYPT: Takes any plain text and returns an encrypted string.
 * The result looks like: "abc123:xyz789" (iv:ciphertext in Base64)
 * 
 * Example:
 *   encrypt("hello world") → "dGhpcw==:abc123XYZ..."
 */
export async function encrypt(plaintext: string): Promise<string> {
  // Don't try to encrypt empty or null values
  if (!plaintext) return plaintext;

  const key = await getDerivedKey();

  // Generate a fresh random IV for every single encryption.
  // This means even if you encrypt the same text twice,
  // you get completely different output each time — very secure.
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    new TextEncoder().encode(plaintext)
  );

  // Convert to Base64 so it can be stored as a normal text string in Supabase
  const ivBase64 = Buffer.from(iv).toString("base64");
  const cipherBase64 = Buffer.from(cipherBuffer).toString("base64");

  // Store as "iv:ciphertext" — we need both parts to decrypt later
  return `${ivBase64}:${cipherBase64}`;
}

/**
 * DECRYPT: Takes an encrypted string and returns the original plain text.
 * 
 * Example:
 *   decrypt("dGhpcw==:abc123XYZ...") → "hello world"
 */
export async function decrypt(ciphertext: string): Promise<string> {
  // If it doesn't have ":" it's probably not encrypted — return as-is
  // This handles old unencrypted rows in the database gracefully
  if (!ciphertext || !ciphertext.includes(":")) return ciphertext;

  const key = await getDerivedKey();

  // Split back into the two parts we stored
  const [ivBase64, cipherBase64] = ciphertext.split(":");

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: Buffer.from(ivBase64, "base64") },
    key,
    Buffer.from(cipherBase64, "base64")
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * ENCRYPT FIELDS: Encrypts specific fields inside an object.
 * 
 * Example:
 *   encryptFields(ticket, ["original_redacted_text", "category"])
 *   Returns the same object but with those two fields encrypted.
 */
export async function encryptFields<T extends Record<string, unknown>>(
  obj: T,
  fields: string[]
): Promise<T> {
  const result = { ...obj }; // Make a copy, never modify the original

  await Promise.all(
    fields.map(async (fieldName) => {
      if (result[fieldName] && typeof result[fieldName] === "string") {
        (result as Record<string, unknown>)[fieldName] = await encrypt(
          result[fieldName] as string
        );
      }
    })
  );

  return result;
}

/**
 * DECRYPT FIELDS: Decrypts specific fields inside an object.
 * 
 * Example:
 *   decryptFields(ticketFromDB, ["original_redacted_text"])
 *   Returns the same object with those fields back to plain text.
 */
export async function decryptFields<T extends Record<string, unknown>>(
  obj: T,
  fields: string[]
): Promise<T> {
  const result = { ...obj };

  await Promise.all(
    fields.map(async (fieldName) => {
      if (result[fieldName] && typeof result[fieldName] === "string") {
        try {
          (result as Record<string, unknown>)[fieldName] = await decrypt(
            result[fieldName] as string
          );
        } catch {
          // This field might be an old unencrypted row — just leave it as-is
          // so old data still works even before migration
          console.warn(
            `[encryption] Could not decrypt field "${fieldName}" — may be legacy unencrypted data`
          );
        }
      }
    })
  );

  return result;
}