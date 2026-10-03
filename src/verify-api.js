'use strict';
// /api/verify 与 /api/verify-batch 的纯逻辑层：解析输入 -> 调用核验内核 -> 组装结构化结果与结果页。
const { verifyProof } = require('./verifier');
const { verifyBatch } = require('./batch');
const { fromHex, toHex, keyHexToNibbles } = require('./hexutil');
const { buildResultPage, buildBatchPage } = require('./page');

// proofNodesText 支持：JSON 数组（["0x..","0x.."]）或按行/逗号/分号分隔的 hex 列表。
function parseProofNodes(text) {
  if (Array.isArray(text)) {
    return text.map((s, i) => {
      if (typeof s !== 'string') throw new Error(`第 ${i + 1} 个 RLP 节点不是字符串`);
      return fromHex(s.trim());
    });
  }
  if (typeof text !== 'string') throw new Error('proofNodes 必须是字符串或字符串数组');
  const trimmed = text.trim();
  if (trimmed.startsWith('[')) {
    let arr;
    try {
      arr = JSON.parse(trimmed);
    } catch (e) {
      throw new Error(`RLP 节点 JSON 数组解析失败：${e.message}`);
    }
    if (!Array.isArray(arr)) throw new Error('RLP 节点 JSON 必须是数组');
    return parseProofNodes(arr);
  }
  const parts = trimmed.split(/[\r\n,;]+/).map((s) => s.trim()).filter((s) => s.length > 0);
  if (parts.length === 0) throw new Error('未提供任何 RLP 节点');
  return parts.map((s) => fromHex(s));
}

// 批量指令标识支持：JSON 数组、多行/逗号/分号分隔；去重后须为 2..8 条。
function parseKeyHexes(text) {
  let items;
  if (Array.isArray(text)) {
    items = text;
  } else if (typeof text === 'string') {
    const trimmed = text.trim();
    if (trimmed.startsWith('[')) {
      try {
        items = JSON.parse(trimmed);
      } catch (e) {
        throw new Error(`指令标识 JSON 数组解析失败：${e.message}`);
      }
    } else {
      items = trimmed.split(/[\r\n,;]+/);
    }
  } else {
    throw new Error('keyHexes 必须是字符串或字符串数组');
  }
  if (!Array.isArray(items)) throw new Error('指令标识必须是数组');
  const seen = new Set();
  const out = [];
  items.forEach((s, i) => {
    if (typeof s !== 'string') throw new Error(`第 ${i + 1} 个指令标识不是字符串`);
    const norm = s.trim().replace(/^0[xX]/, '').toLowerCase();
    if (norm.length === 0) return;
    if (!/^[0-9a-f]+$/.test(norm)) throw new Error(`指令标识 ${s.trim()} 含有非十六进制字符`);
    if (!seen.has(norm)) {
      seen.add(norm);
      out.push(norm);
    }
  });
  if (out.length < 2) throw new Error('批量复核须提交 2 至 8 条不同的十六进制指令标识（当前 0 或 1 条，请使用单指令入口）');
  if (out.length > 8) throw new Error(`批量复核最多 8 条指令标识（当前 ${out.length} 条）`);
  return out;
}

function handleVerify(body) {
  if (!body || typeof body !== 'object') {
    return { httpStatus: 400, error: '请求体必须为 JSON 对象' };
  }
  let rootHash;
  let keyHex;
  let keyNibbles;
  let proofNodes;
  try {
    if (typeof body.rootHash !== 'string') throw new Error('缺少 32 字节根哈希（rootHash）');
    rootHash = fromHex(body.rootHash.trim());
    if (rootHash.length !== 32) throw new Error(`根哈希长度为 ${rootHash.length} 字节，必须为 32 字节`);

    if (typeof body.keyHex !== 'string') throw new Error('缺少十六进制指令标识（keyHex）');
    keyHex = body.keyHex.trim();
    keyNibbles = keyHexToNibbles(keyHex);

    proofNodes = parseProofNodes(body.proofNodes);
  } catch (e) {
    return { httpStatus: 400, error: e.message };
  }

  const result = verifyProof(rootHash, keyNibbles, proofNodes);
  const normalizedKey = keyHex.replace(/^0[xX]/, '').toLowerCase();
  const page = buildResultPage(result, {
    rootHash: toHex(rootHash),
    keyHex: normalizedKey,
    nodeCount: proofNodes.length,
  });
  return { httpStatus: 200, result, page };
}

function handleVerifyBatch(body) {
  if (!body || typeof body !== 'object') {
    return { httpStatus: 400, error: '请求体必须为 JSON 对象' };
  }
  let rootHash;
  let keyHexes;
  let proofNodes;
  try {
    if (typeof body.rootHash !== 'string') throw new Error('缺少 32 字节根哈希（rootHash）');
    rootHash = fromHex(body.rootHash.trim());
    if (rootHash.length !== 32) throw new Error(`根哈希长度为 ${rootHash.length} 字节，必须为 32 字节`);

    keyHexes = parseKeyHexes(body.keyHexes);
    proofNodes = parseProofNodes(body.proofNodes);
  } catch (e) {
    return { httpStatus: 400, error: e.message };
  }

  const batch = verifyBatch(rootHash, keyHexes, proofNodes);
  const page = buildBatchPage(batch, { rootHash: toHex(rootHash), keyHexes, nodeCount: proofNodes.length });
  return { httpStatus: 200, batch, page };
}

module.exports = { handleVerify, handleVerifyBatch, parseProofNodes, parseKeyHexes };
