"use strict";

const crypto = require('crypto');

const DEFAULT_HASH = 'sha256';
const MAX_BYTE_VALUE = 256;

function createOTP({ message, bufferInput }) {
  if ((!message && !bufferInput) || (message && bufferInput)) {
    throw new Error("You must provide either 'message' or 'bufferInput', not both.");
  }

  const input = message ? Buffer.from(message) : bufferInput;
  const otpKey = crypto.randomBytes(input.length);
  const cipher = Buffer.alloc(input.length);

  for (let idx = 0; idx < input.length; idx++) {
    cipher[idx] = input[idx] ^ otpKey[idx];
  }

  return { key: otpKey, ciphertext: cipher };
}

function decryptOTP({ key, ciphertext, outputFormat = 'buffer' }) {
  if (key.length !== ciphertext.length) {
    throw new Error("Key and ciphertext must have identical lengths.");
  }

  const output = Buffer.alloc(key.length);

  for (let i = 0; i < key.length; i++) {
    output[i] = key[i] ^ ciphertext[i];
  }

  if (outputFormat === 'string') {
    return output.toString();
  } else if (outputFormat === 'buffer') {
    return output;
  } else {
    throw new Error(`Unsupported output format: ${outputFormat}`);
  }
}

function generateGUID() {
  return crypto.randomBytes(48).toString('hex');
}

function computeHash(data) {
  return crypto.createHash(DEFAULT_HASH).update(data.toString()).digest('hex');
}

function randomByte() {
  return crypto.randomBytes(1)[0];
}

function randomInt(maxValue) {
  if (maxValue > MAX_BYTE_VALUE) {
    throw new Error(`Limit exceeds maximum byte value (${MAX_BYTE_VALUE}).`);
  }

  const factor = Math.floor(MAX_BYTE_VALUE / maxValue);
  const maxAcceptable = factor * maxValue;
  let rand;

  do {
    rand = randomByte();
  } while (rand >= maxAcceptable);

  return rand % maxValue;
}

module.exports = {
  createOTP,
  decryptOTP,
  generateGUID,
  computeHash,
  randomInt
};

