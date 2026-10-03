'use strict';
// MPT 紧凑十六进制前缀（HP/Compact）编码，解码时严格拒绝非法前缀与尾随噪声。

class HPError extends Error {
  constructor(message) {
    super(message);
    this.name = 'HPError';
  }
}

// nibbles: number[]（元素 0..15）；terminator: boolean
function encode(nibbles, terminator) {
  const flags = terminator ? 2 : 0;
  const out = [];
  if (nibbles.length % 2 === 0) {
    out.push(flags * 16);
    for (let i = 0; i < nibbles.length; i += 2) out.push(nibbles[i] * 16 + nibbles[i + 1]);
  } else {
    out.push(16 + flags * 16 + nibbles[0]);
    for (let i = 1; i < nibbles.length; i += 2) out.push(nibbles[i] * 16 + nibbles[i + 1]);
  }
  return new Uint8Array(out);
}

function decode(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    throw new HPError('十六进制前缀为空');
  }
  const first = bytes[0];
  const terminator = (first & 0x20) !== 0;
  const odd = (first & 0x10) !== 0;
  if ((first & 0xc0) !== 0) {
    throw new HPError(`非法 HP 前缀字节 0x${hex2(first)}：高两位必须为 0`);
  }
  // 偶数长度时首字节低 4 位必须为 0，否则属非规范编码。
  if (!odd && (first & 0x0f) !== 0) {
    throw new HPError(`非法 HP 前缀字节 0x${hex2(first)}：偶数路径的填充半字节必须为 0`);
  }
  const nibbles = [];
  if (odd) nibbles.push(first & 0x0f);
  for (let i = 1; i < bytes.length; i++) {
    nibbles.push(bytes[i] >> 4, bytes[i] & 0x0f);
  }
  return { nibbles, terminator };
}

function hex2(n) {
  return n.toString(16).padStart(2, '0');
}

module.exports = { encode, decode, HPError };
