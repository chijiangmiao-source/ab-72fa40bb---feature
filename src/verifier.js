'use strict';
// 离线 MPT 存在性证明核验内核（浏览器与 Node 共用，零依赖）。
//
// 两种提交方式共用同一套逐层回放逻辑：
//   1. 单指令：verifyProof(rootHash, keyNibbles, proofNodes)
//      proofNodes 为按根到叶排序的 RLP 节点，叶后多余节点判 TAIL_DUPLICATE。
//   2. 批量：verifyBatch(rootHash, entries, poolNodes)
//      一组去重后的 RLP 节点池；每条指令从根开始独立追随分支/扩展/叶引用，
//      只接受能由父节点内嵌内容或 32 字节散列实际抵达的池中节点；
//      未被任何目标路径消费的池节点列为冗余证据。
//
// 单条结果结构：
//   { status: 'authorized' | 'unauthorized' | 'invalid',
//     authorized, value, layers, consumedPath,
//     firstFailedLayer, code, reason,
//     consumedNodeHashes, attemptedNodeHashes }   // 批量模式下填充
const { keccak256 } = require('./keccak');
const rlp = require('./rlp');
const hp = require('./hexpath');
const { toHex, equalBytes, nibblesToHex } = require('./hexutil');

function isBytes(x) {
  return x instanceof Uint8Array;
}

function invalid(code, reason, firstFailedLayer, layers, consumed) {
  return {
    status: 'invalid',
    authorized: false,
    value: null,
    code,
    reason,
    firstFailedLayer,
    layers,
    consumedPath: nibblesToHex(consumed),
  };
}

function nodeDigest(raw) {
  const encoded = rlp.encode(raw);
  return { hash: toHex(keccak256(encoded)), rlpSize: encoded.length, encoded };
}

function hashHex(bytes) {
  return toHex(keccak256(bytes));
}

function kindOf(raw) {
  if (!Array.isArray(raw)) return 'bytes';
  if (raw.length === 17) return 'branch';
  if (raw.length === 2 && isBytes(raw[0])) {
    try {
      return hp.decode(raw[0]).terminator ? 'leaf' : 'extension';
    } catch {
      return 'unknown';
    }
  }
  return 'unknown';
}

// 严格解码节点字节并重编码比对（拒绝非规范/截断编码）。
// 成功 -> { raw }；失败 -> { errorCode, error }。
function strictDecodeNode(nodeBytes, layerNo) {
  if (!isBytes(nodeBytes)) {
    return { errorCode: 'BAD_NODE_BYTES', error: `第 ${layerNo} 层：节点不是字节串` };
  }
  let raw;
  try {
    raw = rlp.decodeCanonical(nodeBytes);
  } catch (e) {
    const noncanon = /非规范|前导零|边界不一致|多余字节/.test(e.message);
    return {
      errorCode: noncanon ? 'RLP_NONCANONICAL' : 'RLP_INVALID',
      error: `第 ${layerNo} 层：RLP ${noncanon ? '非规范编码' : '解码失败（截断/结构错误）'}——${e.message}`,
    };
  }
  let reencoded;
  try {
    reencoded = rlp.encode(raw);
  } catch (e) {
    return { errorCode: 'RLP_INVALID', error: `第 ${layerNo} 层：节点结构无法重新编码——${e.message}` };
  }
  if (!equalBytes(reencoded, nodeBytes)) {
    return {
      errorCode: 'RLP_NONCANONICAL',
      error: `第 ${layerNo} 层：RLP 非规范编码（规范重编码与原字节不一致）`,
    };
  }
  return { raw };
}

// 共用逐层遍历。access 抽象节点来源：
//   locateRoot()                          -> { raw, bytes } | { error:{code,reason} }
//   resolveHash(ref, childLayerNo)        -> { raw, bytes } | { errorCode, error }
//   tailExtra()                           -> 叶/值槽之后仍未消费的节点数（仅单指令有序模式非 0）
//   onEnterNode(bytes, viaHashRef)        -> 成功进入某节点时的消费记账回调
function runTraversal(rootHash, keyNibbles, access) {
  const layers = []; // 已成功核验并回放的层
  const consumed = [];

  const root = access.locateRoot();
  if (root.error) {
    return invalid(root.error.code, root.error.reason, 1, layers, consumed);
  }
  let node = root.raw;
  let nodeRef = { mode: 'root-commitment' }; // 当前节点的引用方式
  access.onEnterNode(root.bytes, false);
  let remainder = keyNibbles.slice();

  // 内嵌节点直接取自父节点已解码的 RLP 负载；散列引用交给 access 在节点池中解析。
  const resolveChild = (ref, childLayerNo) => {
    if (Array.isArray(ref)) {
      const encoded = rlp.encode(ref);
      if (encoded.length >= 32) {
        return { errorCode: 'BAD_REF', error: `内嵌节点 RLP 长度 ${encoded.length} ≥ 32，按规范必须改为 32 字节散列引用` };
      }
      return { raw: ref, embedded: true };
    }
    if (!isBytes(ref) || ref.length !== 32) {
      return { errorCode: 'BAD_REF', error: '子引用既非内嵌 RLP 列表也非 32 字节散列' };
    }
    const found = access.resolveHash(ref, childLayerNo);
    if (found.errorCode || found.error) return found;
    return { raw: found.raw, bytes: found.bytes, embedded: false };
  };

  for (;;) {
    const layerNo = layers.length + 1;

    if (!Array.isArray(node) || (node.length !== 2 && node.length !== 17)) {
      return invalid('NODE_MALFORMED', `第 ${layerNo} 层：节点既非 2 项（叶/扩展）也非 17 项（分支）`, layerNo, layers, consumed);
    }

    // 2 项节点：以 HP 终止标志区分叶节点与扩展节点。
    if (node.length === 2) {
      const [pathBytes, second] = node;
      if (!isBytes(pathBytes)) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：路径字段必须是字节串`, layerNo, layers, consumed);
      }
      let hpDec;
      try {
        hpDec = hp.decode(pathBytes);
      } catch (e) {
        return invalid('HP_INVALID', `第 ${layerNo} 层：十六进制前缀错误——${e.message}`, layerNo, layers, consumed);
      }

      // ---------------- 叶节点 ----------------
      if (hpDec.terminator) {
        if (!isBytes(second)) {
          return invalid('NODE_MALFORMED', `第 ${layerNo} 层：叶节点值必须是字节串`, layerNo, layers, consumed);
        }
        const path = hpDec.nibbles;
        if (remainder.length !== path.length || path.some((n, i) => n !== remainder[i])) {
          return invalid(
            'PATH_MISMATCH',
            `第 ${layerNo} 层：路径残缺/偏离——叶路径 ${nibblesToHex(path)} 与剩余半字节 ${nibblesToHex(remainder)} 不一致`,
            layerNo,
            layers,
            consumed
          );
        }
        const digest = nodeDigest(node);
        for (const n of path) consumed.push(n);
        layers.push({
          layer: layerNo,
          kind: 'leaf',
          reference: nodeRef.mode,
          embeddedInLayer: nodeRef.parentLayer ?? null,
          nodeHash: digest.hash,
          rlpSize: digest.rlpSize,
          hpPrefix: toHex(pathBytes),
          consumedNibbles: nibblesToHex(path),
          cumulativePath: nibblesToHex(consumed),
          value: toHex(second),
        });
        const tailExtra = access.tailExtra();
        if (tailExtra > 0) {
          return invalid(
            'TAIL_DUPLICATE',
            `叶节点之后仍有 ${tailExtra} 个未消费节点（重复尾节点/冗余证据）`,
            layerNo + 1,
            layers,
            consumed
          );
        }
        const value = second;
        const authorized = value.length === 1 && value[0] === 0x01;
        return {
          status: authorized ? 'authorized' : 'unauthorized',
          authorized,
          value: toHex(value),
          code: null,
          reason: null,
          firstFailedLayer: null,
          layers,
          consumedPath: nibblesToHex(consumed),
        };
      }

      // ---------------- 扩展节点 ----------------
      if (hpDec.nibbles.length === 0) {
        return invalid('HP_INVALID', `第 ${layerNo} 层：十六进制前缀错误——扩展节点路径为空`, layerNo, layers, consumed);
      }
      const path = hpDec.nibbles;
      if (remainder.length < path.length || path.some((n, i) => n !== remainder[i])) {
        return invalid(
          'PATH_MISMATCH',
          `第 ${layerNo} 层：路径残缺/偏离——扩展路径 ${nibblesToHex(path)} 与剩余半字节 ${nibblesToHex(remainder)} 不匹配`,
          layerNo,
          layers,
          consumed
        );
      }

      const digest = nodeDigest(node);
      const child = resolveChild(second, layerNo + 1);
      const childRefMode = Array.isArray(second) ? 'embedded-node' : 'hash-32';
      layers.push({
        layer: layerNo,
        kind: 'extension',
        reference: nodeRef.mode,
        embeddedInLayer: nodeRef.parentLayer ?? null,
        nodeHash: digest.hash,
        rlpSize: digest.rlpSize,
        hpPrefix: toHex(pathBytes),
        consumedNibbles: nibblesToHex(path),
        cumulativePath: nibblesToHex(consumed.concat(path)),
        childReference: childRefMode,
        childHash: childRefMode === 'hash-32' ? toHex(second) : null,
      });
      if (child.errorCode) {
        const atLayer = child.errorCode === 'BAD_REF' ? layerNo : layerNo + 1;
        return invalid(child.errorCode, `第 ${atLayer} 层：${child.error}`, atLayer, layers, consumed);
      }
      for (const n of path) consumed.push(n);
      node = child.raw;
      if (!child.embedded) access.onEnterNode(child.bytes, true);
      nodeRef = child.embedded ? { mode: 'embedded-node', parentLayer: layerNo } : { mode: 'hash-32' };
      remainder = remainder.slice(path.length);
      continue;
    }

    // ---------------- 分支节点（17 项）----------------
    for (let i = 0; i < 17; i++) {
      const item = node[i];
      if (!(isBytes(item) || Array.isArray(item))) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：分支槽 ${i} 类型非法`, layerNo, layers, consumed);
      }
      // 槽 0..15 为子节点引用：只允许空串、32 字节散列或内嵌列表；槽 16 为值槽，允许任意字节串。
      if (i < 16 && isBytes(item) && item.length !== 0 && item.length !== 32) {
        return invalid('BAD_REF', `第 ${layerNo} 层：分支槽 ${i} 的字节串长度为 ${item.length}，只允许空串或 32 字节散列`, layerNo, layers, consumed);
      }
      if (i === 16 && Array.isArray(item)) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：分支值槽（16）必须为字节串或空`, layerNo, layers, consumed);
      }
    }

    if (remainder.length === 0) {
      const v = node[16];
      if (!isBytes(v) || v.length === 0) {
        return invalid('PATH_INCOMPLETE', `第 ${layerNo} 层：路径残缺——半字节已耗尽但分支值槽为空`, layerNo, layers, consumed);
      }
      const digest = nodeDigest(node);
      layers.push({
        layer: layerNo,
        kind: 'branch-value',
        reference: nodeRef.mode,
        embeddedInLayer: nodeRef.parentLayer ?? null,
        nodeHash: digest.hash,
        rlpSize: digest.rlpSize,
        slot: 16,
        consumedNibbles: '',
        cumulativePath: nibblesToHex(consumed),
        value: toHex(v),
      });
      const tailExtra = access.tailExtra();
      if (tailExtra > 0) {
        return invalid('TAIL_DUPLICATE', `第 ${layerNo + 1} 层：抵达终值后仍有 ${tailExtra} 个未消费的重复尾节点`, layerNo + 1, layers, consumed);
      }
      const authorized = v.length === 1 && v[0] === 0x01;
      return {
        status: authorized ? 'authorized' : 'unauthorized',
        authorized,
        value: toHex(v),
        code: null,
        reason: null,
        firstFailedLayer: null,
        layers,
        consumedPath: nibblesToHex(consumed),
      };
    }

    const idx = remainder[0];
    const slot = node[idx];
    if (isBytes(slot) && slot.length === 0) {
      return invalid('PATH_INCOMPLETE', `第 ${layerNo} 层：路径残缺——分支槽 ${idx.toString(16)} 为空`, layerNo, layers, consumed);
    }
    const digest = nodeDigest(node);
    const child = resolveChild(slot, layerNo + 1);
    const childRefMode = Array.isArray(slot) ? 'embedded-node' : 'hash-32';
    layers.push({
      layer: layerNo,
      kind: 'branch',
      reference: nodeRef.mode,
      embeddedInLayer: nodeRef.parentLayer ?? null,
      nodeHash: digest.hash,
      rlpSize: digest.rlpSize,
      slot: idx,
      consumedNibbles: idx.toString(16),
      cumulativePath: nibblesToHex(consumed.concat([idx])),
      childReference: childRefMode,
      childHash: childRefMode === 'hash-32' ? toHex(slot) : null,
    });
    if (child.errorCode) {
      const atLayer = child.errorCode === 'BAD_REF' ? layerNo : layerNo + 1;
      return invalid(child.errorCode, `第 ${atLayer} 层：${child.error}`, atLayer, layers, consumed);
    }
    consumed.push(idx);
    node = child.raw;
    if (!child.embedded) access.onEnterNode(child.bytes, true);
    nodeRef = child.embedded ? { mode: 'embedded-node', parentLayer: layerNo } : { mode: 'hash-32' };
    remainder = remainder.slice(1);
  }
}

// ---------------------------------------------------------------------------
// 单指令提交：proofNodes 按根到叶排序，保持原有逐层回放与 TAIL_DUPLICATE 语义。
// ---------------------------------------------------------------------------
function verifyProof(rootHash, keyNibbles, proofNodes) {
  const layers = [];
  const consumed = [];

  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) {
    return invalid('BAD_ROOT', '根哈希必须为 32 字节', 0, layers, consumed);
  }
  if (!Array.isArray(keyNibbles) || keyNibbles.some((n) => !Number.isInteger(n) || n < 0 || n > 15)) {
    return invalid('BAD_KEY', '十六进制指令标识必须为十六进制半字节序列（字符 0..f，可为奇数长度）', 0, layers, consumed);
  }
  if (!Array.isArray(proofNodes) || proofNodes.length === 0) {
    return invalid('EMPTY_PROOF', '证明为空：至少需要根节点', 1, layers, consumed);
  }

  // 严格解码每个 RLP 节点，并要求重编码与原字节逐字节一致（拒绝非规范/截断编码）。
  const decoded = [];
  for (let i = 0; i < proofNodes.length; i++) {
    const d = strictDecodeNode(proofNodes[i], i + 1);
    if (d.errorCode) return invalid(d.errorCode, d.error, i + 1, layers, consumed);
    decoded.push(d.raw);
  }

  // 根承诺核验
  const rootDigest = keccak256(proofNodes[0]);
  if (!equalBytes(rootDigest, rootHash)) {
    return invalid(
      'ROOT_MISMATCH',
      `父子引用不符：根节点散列 0x${toHex(rootDigest)} 与提交的 32 字节根哈希 0x${toHex(rootHash)} 不一致`,
      1,
      layers,
      consumed
    );
  }

  let proofIdx = 1; // 下一个待消费的散列引用证明节点
  const consumedNodeHashes = [hashHex(proofNodes[0])];
  const access = {
    locateRoot() {
      return { raw: decoded[0], bytes: proofNodes[0] };
    },
    onEnterNode(bytes) {
      consumedNodeHashes.push(hashHex(bytes));
    },
    resolveChild: undefined,
    resolveHash(ref) {
      if (proofIdx >= decoded.length) {
        return { errorCode: 'PATH_INCOMPLETE', error: `路径残缺——散列引用 0x${toHex(ref)} 缺少对应证明节点` };
      }
      const nextBytes = proofNodes[proofIdx];
      if (!equalBytes(keccak256(nextBytes), ref)) {
        return {
          errorCode: 'REF_MISMATCH',
          error: `父子引用不符——子节点散列 0x${hashHex(nextBytes)} 不等于父节点引用 0x${toHex(ref)}`,
        };
      }
      const raw = decoded[proofIdx];
      proofIdx += 1;
      return { raw, bytes: nextBytes };
    },
    tailExtra() {
      return decoded.length - proofIdx;
    },
  };

  const result = runTraversal(rootHash, keyNibbles, access);
  result.consumedNodeHashes = Array.from(new Set(consumedNodeHashes));
  result.attemptedNodeHashes = result.consumedNodeHashes.slice();
  return result;
}

// ---------------------------------------------------------------------------
// 批量提交：去重 RLP 节点池。解析完全惰性——只解码路径实际抵达的池节点，
// 某条指令的失败绝不影响同批其余指令。
// ---------------------------------------------------------------------------
function verifyProofFromPool(rootHash, keyNibbles, pool) {
  const layers = [];
  const consumed = [];

  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) {
    return invalid('BAD_ROOT', '根哈希必须为 32 字节', 0, layers, consumed);
  }
  if (!Array.isArray(keyNibbles) || keyNibbles.some((n) => !Number.isInteger(n) || n < 0 || n > 15)) {
    return invalid('BAD_KEY', '十六进制指令标识必须为十六进制半字节序列（字符 0..f，可为奇数长度）', 0, layers, consumed);
  }
  if (!Array.isArray(pool) || pool.length === 0) {
    return invalid('EMPTY_PROOF', '节点池为空：至少需要根节点', 1, layers, consumed);
  }
  for (const nodeBytes of pool) {
    if (!isBytes(nodeBytes)) {
      return invalid('BAD_NODE_BYTES', '节点池中存在非字节串节点', 0, layers, consumed);
    }
  }

  // 以节点摘要为键：池节点只能由父节点的 32 字节散列引用实际“抵达”。
  const byHash = new Map();
  for (const bytes of pool) byHash.set(hashHex(bytes), bytes);

  const consumedNodeHashes = [];
  const attemptedNodeHashes = [];
  const remember = (arr, h) => {
    if (!arr.includes(h)) arr.push(h);
  };

  const access = {
    locateRoot() {
      const h = toHex(rootHash);
      remember(attemptedNodeHashes, h);
      const bytes = byHash.get(h);
      if (!bytes) {
        return { error: { code: 'ROOT_MISMATCH', reason: `父子引用不符：去重节点池中没有任何节点的 Keccak 摘要等于根哈希 0x${h}` } };
      }
      const d = strictDecodeNode(bytes, 1);
      if (d.errorCode) return { error: { code: d.errorCode, reason: d.error } };
      return { raw: d.raw, bytes };
    },
    onEnterNode(bytes) {
      remember(consumedNodeHashes, hashHex(bytes));
    },
    resolveHash(ref, childLayerNo) {
      const h = toHex(ref);
      remember(attemptedNodeHashes, h);
      const bytes = byHash.get(h);
      if (!bytes) {
        return { errorCode: 'PATH_INCOMPLETE', error: `路径残缺——去重节点池中缺少散列引用 0x${h} 对应的节点` };
      }
      const d = strictDecodeNode(bytes, childLayerNo);
      if (d.errorCode) return { errorCode: d.errorCode, error: d.error };
      remember(consumedNodeHashes, h);
      return { raw: d.raw, bytes };
    },
    tailExtra() {
      return 0; // 池模式下未消费节点统一归入冗余证据，不在路径终点判错
    },
  };

  const result = runTraversal(rootHash, keyNibbles, access);
  result.consumedNodeHashes = consumedNodeHashes;
  result.attemptedNodeHashes = attemptedNodeHashes;
  return result;
}

// 节点池按原始字节去重（规范 RLP 下字节相同即同一节点）。
function dedupePool(nodes) {
  const seen = new Set();
  const unique = [];
  let duplicates = 0;
  for (const bytes of nodes) {
    const h = hashHex(bytes);
    if (seen.has(h)) {
      duplicates += 1;
      continue;
    }
    seen.add(h);
    unique.push(bytes);
  }
  return { nodes: unique, duplicates };
}

// 批量核验：entries = [{ keyHex, nibbles:number[]|null, parseError:string|null }]。
// 返回每条指令相互独立的结论、共享节点复用表与冗余证据清单。
function verifyBatch(rootHash, entries, poolNodes) {
  const results = entries.map((entry) => {
    if (entry.parseError || !Array.isArray(entry.nibbles)) {
      return {
        keyHex: entry.keyHex,
        status: 'invalid',
        authorized: false,
        value: null,
        code: 'BAD_KEY',
        reason: `十六进制指令标识无法解析：${entry.parseError || '不是有效的半字节序列'}`,
        firstFailedLayer: 0,
        layers: [],
        consumedPath: '',
        consumedNodeHashes: [],
        attemptedNodeHashes: [],
      };
    }
    const r = verifyProofFromPool(rootHash, entry.nibbles, poolNodes);
    r.keyHex = entry.keyHex;
    r.consumedNodeHashes = r.consumedNodeHashes || [];
    r.attemptedNodeHashes = r.attemptedNodeHashes || [];
    return r;
  });

  // 共享节点：以成功回放层上的节点摘要汇总（含内嵌节点；inPool 标记其是否独立池条目）。
  const poolHashes = new Set(poolNodes.map(hashHex));
  const users = new Map(); // nodeHash -> Map(指令序号 -> 'hash-32' | 'embedded-node' | 'root')
  const firstSeenOrder = [];
  results.forEach((r, idx) => {
    for (const layer of r.layers) {
      if (!users.has(layer.nodeHash)) {
        users.set(layer.nodeHash, new Map());
        firstSeenOrder.push(layer.nodeHash);
      }
      const mode = layer.reference === 'embedded-node' ? 'embedded-node' : 'hash-32';
      users.get(layer.nodeHash).set(idx, mode);
    }
  });
  const reuse = firstSeenOrder
    .map((nodeHash) => {
      const keyIndexes = Array.from(users.get(nodeHash).keys());
      const modes = keyIndexes.map((i) => users.get(nodeHash).get(i));
      return {
        nodeHash,
        reuseCount: keyIndexes.length,
        keyIndexes,
        modes,
        embedded: modes.some((m) => m === 'embedded-node'),
        inPool: poolHashes.has(nodeHash),
      };
    })
    .filter((e) => e.reuseCount >= 2);

  // 冗余证据：既未被任何路径成功消费、也未被失败路径实际引用到的池节点。
  // 注意内嵌在途节点同样计入 touched——它虽不占独立散列引用，但确属目标路径的一部分。
  const touched = new Set();
  for (const r of results) {
    for (const layer of r.layers) touched.add(layer.nodeHash);
    for (const h of r.consumedNodeHashes) touched.add(h);
    for (const h of r.attemptedNodeHashes) touched.add(h);
  }
  const redundant = [];
  for (const bytes of poolNodes) {
    const nodeHash = hashHex(bytes);
    if (touched.has(nodeHash)) continue;
    let kind = 'unparseable';
    try {
      kind = kindOf(rlp.decodeCanonical(bytes));
    } catch {
      // 不可解码的池节点仍可列为冗余证据（它从未被任何路径接受）。
    }
    redundant.push({ nodeHash, rlpSize: bytes.length, kind });
  }

  const summary = { authorized: 0, unauthorized: 0, invalid: 0 };
  for (const r of results) summary[r.status] += 1;

  return {
    kind: 'batch',
    rootHash: toHex(rootHash),
    poolSize: poolNodes.length,
    results,
    reuse,
    redundant,
    summary,
  };
}

module.exports = { verifyProof, verifyProofFromPool, verifyBatch, dedupePool, kindOf, nodeDigest };
