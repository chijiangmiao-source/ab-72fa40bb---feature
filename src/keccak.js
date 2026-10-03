'use strict';
// Keccak-256（以太坊使用的填充 0x01 变体），纯 JS 零依赖实现。
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROT = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const MASK = 0xffffffffffffffffn;

function rotl64(x, n) {
  return n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK;
}

// 输入：Uint8Array；输出：32 字节 Uint8Array
function keccak256(input) {
  const rate = 136; // 1088 bit
  const state = new BigUint64Array(25);

  const absorb = (block) => {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 0; b < 8; b++) lane |= BigInt(block[i * 8 + b]) << BigInt(b * 8);
      state[i] ^= lane;
    }
    keccakF(state);
  };

  let offset = 0;
  while (input.length - offset >= rate) {
    absorb(input.subarray(offset, offset + rate));
    offset += rate;
  }
  const last = new Uint8Array(rate);
  last.set(input.subarray(offset));
  last[input.length - offset] = 0x01; // Keccak 填充（非 SHA3 的 0x06）
  last[rate - 1] |= 0x80;
  absorb(last);

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((lane >> BigInt(b * 8)) & 0xffn);
  }
  return out;
}

function keccakF(a) {
  for (let round = 0; round < 24; round++) {
    // θ
    const c = new BigUint64Array(5);
    for (let x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) a[x + 5 * y] ^= d;
    }
    // ρ 与 π
    const b = new BigUint64Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const nx = y;
        const ny = (2 * x + 3 * y) % 5;
        b[nx + 5 * ny] = rotl64(a[x + 5 * y], ROT[x][y]);
      }
    }
    // χ
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        a[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & MASK) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // ι
    a[0] ^= RC[round];
  }
}

module.exports = { keccak256 };
