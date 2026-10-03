'use strict';
// 字节与十六进制工具（Node 与浏览器共用，零依赖）。

function toHex(bytes, prefix = false) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('期望 Uint8Array');
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return prefix ? '0x' + s : s;
}

function fromHex(hex) {
  if (typeof hex !== 'string') throw new TypeError('期望十六进制字符串');
  let s = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) throw new Error('十六进制字符串长度必须为偶数');
  if (s.length > 0 && !/^[0-9a-fA-F]*$/.test(s)) throw new Error('含有非十六进制字符');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToNibbles(bytes) {
  const n = [];
  for (const b of bytes) n.push(b >> 4, b & 0x0f);
  return n;
}

// 十六进制指令标识 -> 半字节序列；允许奇数长度（如 "abc" -> [a,b,c]）。
function keyHexToNibbles(hex) {
  if (typeof hex !== 'string') throw new TypeError('期望十六进制字符串');
  let s = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error('十六进制指令标识含有非十六进制字符');
  return Array.from(s, (c) => parseInt(c, 16));
}

function nibblesToHex(nibbles) {
  return nibbles.map((x) => x.toString(16)).join('');
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

module.exports = { toHex, fromHex, bytesToNibbles, keyHexToNibbles, nibblesToHex, equalBytes };
