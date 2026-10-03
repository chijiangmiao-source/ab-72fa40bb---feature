'use strict';
// 严格、规范化（canonical）RLP：解码时拒绝所有非规范编码与截断输入。
// 节点表示为数组，字节串表示为 Uint8Array。

class RLPError extends Error {
  constructor(message, offset) {
    super(offset === undefined ? message : `${message}（偏移 ${offset}）`);
    this.name = 'RLPError';
    this.offset = offset;
  }
}

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function encodeLength(len, offset) {
  if (len < 56) return new Uint8Array([offset + len]);
  const bytes = [];
  let x = len;
  while (x > 0) {
    bytes.push(x & 0xff);
    x = Math.floor(x / 256);
  }
  bytes.reverse();
  const out = new Uint8Array(1 + bytes.length);
  out[0] = offset + 55 + bytes.length;
  out.set(bytes, 1);
  return out;
}

function encode(item) {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return new Uint8Array(item);
    return concatBytes([encodeLength(item.length, 0x80), item]);
  }
  if (Array.isArray(item)) {
    const payload = concatBytes(item.map(encode));
    return concatBytes([encodeLength(payload.length, 0xc0), payload]);
  }
  throw new TypeError('RLP 仅接受 Uint8Array 或数组');
}

function toBytes(thing) {
  if (thing instanceof Uint8Array) return thing;
  if (Array.isArray(thing)) return encode(thing);
  throw new TypeError('类型不受支持');
}

// 解码：strict=false 时宽容处理非规范编码（但仍拒绝截断/越界/深度超限）；
// strict=true 时额外拒绝一切非规范形式（单字节长形式、长度长形短用、前导零等）。
function decodePartial(data, start, depth, strict) {
  if (depth > 64) throw new RLPError('嵌套深度超限', start);
  if (start >= data.length) throw new RLPError('输入截断：缺少首字节', start);
  const first = data[start];

  if (first < 0x80) {
    // 单字节自身即值；0x00..0x7f 全部合法。
    return { value: new Uint8Array([first]), length: 1 };
  }

  if (first < 0xb8) {
    const len = first - 0x80;
    const s = start + 1;
    if (s + len > data.length) throw new RLPError('输入截断：短串数据缺失', start);
    if (strict && len === 1 && data[s] < 0x80) {
      throw new RLPError('非规范 RLP：单字节应以原始形式编码', start);
    }
    return { value: data.slice(s, s + len), length: 1 + len };
  }

  if (first < 0xc0) {
    const lenOfLen = first - 0xb7;
    if (lenOfLen > 8) throw new RLPError('长度前缀过长', start);
    const s = start + 1;
    if (s + lenOfLen > data.length) throw new RLPError('输入截断：长度前缀不完整', start);
    let len = 0;
    for (let i = 0; i < lenOfLen; i++) len = len * 256 + data[s + i];
    const v = s + lenOfLen;
    if (!Number.isSafeInteger(len) || v + len > data.length) {
      throw new RLPError('输入截断：长串数据超出输入', start);
    }
    if (strict) {
      if (len < 56) throw new RLPError('非规范 RLP：长串长度应使用短形式', start);
      if (data[s] === 0) throw new RLPError('非规范 RLP：长度含前导零', start);
    }
    return { value: data.slice(v, v + len), length: lenOfLen + 1 + len };
  }

  if (first < 0xf8) {
    const payloadLen = first - 0xc0;
    const s = start + 1;
    if (s + payloadLen > data.length) throw new RLPError('输入截断：短列表负载超出输入', start);
    return decodeListPayload(data, s, payloadLen, start, depth, strict);
  }

  const lenOfLen = first - 0xf7;
  if (lenOfLen > 8) throw new RLPError('列表长度前缀过长', start);
  const s = start + 1;
  if (s + lenOfLen > data.length) throw new RLPError('输入截断：列表长度前缀不完整', start);
  let payloadLen = 0;
  for (let i = 0; i < lenOfLen; i++) payloadLen = payloadLen * 256 + data[s + i];
  const v = s + lenOfLen;
  if (!Number.isSafeInteger(payloadLen) || v + payloadLen > data.length) {
    throw new RLPError('输入截断：长列表负载超出输入', start);
  }
  if (strict) {
    if (payloadLen < 56) throw new RLPError('非规范 RLP：长列表长度应使用短形式', start);
    if (data[s] === 0) throw new RLPError('非规范 RLP：列表长度含前导零', start);
  }
  return decodeListPayload(data, v, payloadLen, start, depth, strict);
}

function decodeListPayload(data, payloadStart, payloadLen, itemStart, depth, strict) {
  const items = [];
  let cursor = payloadStart;
  const end = payloadStart + payloadLen;
  while (cursor < end) {
    const part = decodePartial(data, cursor, depth + 1, strict);
    items.push(part.value);
    cursor += part.length;
  }
  if (cursor !== end) throw new RLPError('非规范 RLP：列表负载边界不一致', itemStart);
  return { value: items, length: end - itemStart };
}

// 宽容解码：拒绝截断/越界，但接受非规范形式（调用方可再做规范重编码比对）。
function decode(input) {
  return decodeWithMode(input, false);
}

// 严格解码：在宽容解码基础上拒绝一切非规范编码。
function decodeCanonical(input) {
  return decodeWithMode(input, true);
}

function decodeWithMode(input, strict) {
  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (data.length === 0) throw new RLPError('输入为空，无法解码', 0);
  const result = decodePartial(data, 0, 0, strict);
  if (result.length !== data.length) {
    throw new RLPError('非规范 RLP：首个项之后存在多余字节', result.length);
  }
  return result.value;
}

module.exports = { encode, decode, decodeCanonical, toBytes, RLPError };
