"use strict";

(function exposeBlake3(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.SsvBlake3 = api;
}(typeof globalThis === "undefined" ? undefined : globalThis, () => {
  const IV = Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const MESSAGE_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
  const CHUNK_START = 1;
  const CHUNK_END = 2;
  const ROOT = 8;
  const DERIVE_KEY_CONTEXT = 32;
  const DERIVE_KEY_MATERIAL = 64;
  const BLOCK_LENGTH = 64;
  const CHUNK_LENGTH = 1024;
  const textEncoder = new TextEncoder();

  function rotateRight(value, amount) {
    return ((value >>> amount) | (value << (32 - amount))) >>> 0;
  }

  function mix(state, a, b, c, d, left, right) {
    state[a] = (state[a] + state[b] + left) >>> 0;
    state[d] = rotateRight((state[d] ^ state[a]) >>> 0, 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateRight((state[b] ^ state[c]) >>> 0, 12);
    state[a] = (state[a] + state[b] + right) >>> 0;
    state[d] = rotateRight((state[d] ^ state[a]) >>> 0, 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotateRight((state[b] ^ state[c]) >>> 0, 7);
  }

  function round(state, message) {
    mix(state, 0, 4, 8, 12, message[0], message[1]);
    mix(state, 1, 5, 9, 13, message[2], message[3]);
    mix(state, 2, 6, 10, 14, message[4], message[5]);
    mix(state, 3, 7, 11, 15, message[6], message[7]);
    mix(state, 0, 5, 10, 15, message[8], message[9]);
    mix(state, 1, 6, 11, 12, message[10], message[11]);
    mix(state, 2, 7, 8, 13, message[12], message[13]);
    mix(state, 3, 4, 9, 14, message[14], message[15]);
  }

  function permute(message) {
    return Uint32Array.from(MESSAGE_PERMUTATION, (index) => message[index]);
  }

  function compress(chainingValue, blockWords, counter, blockLength, flags) {
    const state = new Uint32Array(16);
    state.set(chainingValue, 0);
    state.set(IV.subarray(0, 4), 8);
    state[12] = Number(counter & 0xffffffffn);
    state[13] = Number((counter >> 32n) & 0xffffffffn);
    state[14] = blockLength;
    state[15] = flags;

    let message = blockWords;
    for (let roundIndex = 0; roundIndex < 7; roundIndex += 1) {
      round(state, message);
      if (roundIndex !== 6) message = permute(message);
    }

    const output = new Uint32Array(16);
    for (let index = 0; index < 8; index += 1) {
      output[index] = (state[index] ^ state[index + 8]) >>> 0;
      output[index + 8] = (state[index + 8] ^ chainingValue[index]) >>> 0;
    }
    return output;
  }

  function blockWords(bytes) {
    const words = new Uint32Array(16);
    for (let index = 0; index < bytes.length; index += 1) {
      words[index >>> 2] |= bytes[index] << (8 * (index & 3));
    }
    return words;
  }

  function wordsBytes(words) {
    const bytes = new Uint8Array(words.length * 4);
    for (let index = 0; index < words.length; index += 1) {
      const word = words[index];
      bytes[4 * index] = word;
      bytes[4 * index + 1] = word >>> 8;
      bytes[4 * index + 2] = word >>> 16;
      bytes[4 * index + 3] = word >>> 24;
    }
    return bytes;
  }

  function keyWords(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new TypeError("a BLAKE3 key must contain exactly 32 bytes");
    }
    return blockWords(bytes).slice(0, 8);
  }

  // Protocol derivations are deliberately bounded to one BLAKE3 chunk. The
  // instance seed and every registered ASCII domain label are far below 1 KiB.
  function chunkOutput(input, initialChainingValue, flags) {
    if (!(input instanceof Uint8Array)) throw new TypeError("BLAKE3 input must be bytes");
    if (input.length > CHUNK_LENGTH) throw new RangeError("BLAKE3 preview input exceeds one chunk");

    const blockCount = Math.max(1, Math.ceil(input.length / BLOCK_LENGTH));
    let chainingValue = initialChainingValue.slice();
    for (let blockIndex = 0; blockIndex + 1 < blockCount; blockIndex += 1) {
      const start = blockIndex * BLOCK_LENGTH;
      const words = blockWords(input.subarray(start, start + BLOCK_LENGTH));
      const blockFlags = flags | (blockIndex === 0 ? CHUNK_START : 0);
      chainingValue = compress(chainingValue, words, 0n, BLOCK_LENGTH, blockFlags).slice(0, 8);
    }

    const finalIndex = blockCount - 1;
    const finalStart = finalIndex * BLOCK_LENGTH;
    const finalBlock = input.subarray(finalStart, finalStart + BLOCK_LENGTH);
    return {
      chainingValue,
      block: blockWords(finalBlock),
      blockLength: finalBlock.length,
      flags: flags | CHUNK_END | (finalIndex === 0 ? CHUNK_START : 0),
    };
  }

  class OutputReader {
    constructor(output) {
      this.output = output;
      this.counter = 0n;
      this.block = new Uint8Array(0);
      this.offset = 0;
    }

    read(length) {
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new RangeError("BLAKE3 output length must be a nonnegative safe integer");
      }
      const result = new Uint8Array(length);
      let written = 0;
      while (written < length) {
        if (this.offset === this.block.length) {
          const words = compress(
            this.output.chainingValue,
            this.output.block,
            this.counter,
            this.output.blockLength,
            this.output.flags | ROOT,
          );
          this.block = wordsBytes(words);
          this.offset = 0;
          this.counter += 1n;
        }
        const available = Math.min(length - written, this.block.length - this.offset);
        result.set(this.block.subarray(this.offset, this.offset + available), written);
        this.offset += available;
        written += available;
      }
      return result;
    }
  }

  function hash(input, length = 32) {
    return new OutputReader(chunkOutput(input, IV, 0)).read(length);
  }

  function deriveKeyReader(context, input) {
    if (typeof context !== "string") throw new TypeError("BLAKE3 context must be text");
    const contextKey = new OutputReader(
      chunkOutput(textEncoder.encode(context), IV, DERIVE_KEY_CONTEXT),
    ).read(32);
    return new OutputReader(chunkOutput(input, keyWords(contextKey), DERIVE_KEY_MATERIAL));
  }

  function deriveKey(context, input, length = 32) {
    return deriveKeyReader(context, input).read(length);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function hexToBytes(hex) {
    if (typeof hex !== "string" || !/^(?:[0-9a-f]{2})*$/.test(hex)) {
      throw new TypeError("hex must contain lowercase byte pairs");
    }
    return Uint8Array.from(
      { length: hex.length / 2 },
      (_, index) => Number.parseInt(hex.slice(2 * index, 2 * index + 2), 16),
    );
  }

  function u64LittleEndian(value) {
    if (typeof value !== "bigint" || value < 0n || value >= (1n << 64n)) {
      throw new RangeError("value must fit an unsigned 64-bit integer");
    }
    return Uint8Array.from({ length: 8 }, (_, index) => Number((value >> BigInt(8 * index)) & 0xffn));
  }

  function concatenate(...arrays) {
    const length = arrays.reduce((total, bytes) => total + bytes.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const bytes of arrays) {
      result.set(bytes, offset);
      offset += bytes.length;
    }
    return result;
  }

  return {
    bytesToHex,
    concatenate,
    deriveKey,
    deriveKeyReader,
    hash,
    hexToBytes,
    textEncoder,
    u64LittleEndian,
  };
}));
