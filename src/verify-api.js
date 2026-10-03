'use strict';
// /api/verify 的纯逻辑层：解析输入 -> 调用核验内核 -> 组装结构化结果与结果页。
const { verifyProof } = require('./verifier');
const { fromHex, toHex, keyHexToNibbles } = require('./hexutil');
const { buildResultPage } = require('./page');

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

module.exports = { handleVerify, parseProofNodes };
