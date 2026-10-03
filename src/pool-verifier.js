'use strict';
// 批量复核内核：在去重的 RLP 节点池中，为单条指令标识从根开始独立追随引用。
//
// 与 verifier.js 的“按根到叶排序的顺序证明”不同，批量模式下提交的是无序节点池：
//   - 根节点由 32 字节根哈希在池中定位；
//   - 每个 32 字节散列引用按其 Keccak-256 摘要在池中解析，找不到即路径残缺；
//   - 内嵌节点（父 RLP 内联、< 32 字节）直接递归进入，不在池中单独占位；
// 因而只有能由“当前父节点的内嵌内容或 32 字节散列”实际抵达的池节点才会被接受，
// 池中存在但无法从根抵达的节点不会被消费（由批量聚合层归类为冗余证据）。
//
// 输出结构与 verifier.verifyProof 同构（供结果页共用逐层回放渲染），
// 额外返回 reached：本路径实际抵达的池节点序号（含失败层节点，不含内嵌节点）。
const { keccak256 } = require('./keccak');
const rlp = require('./rlp');
const hp = require('./hexpath');
const { toHex, equalBytes, nibblesToHex } = require('./hexutil');

function isBytes(x) {
  return x instanceof Uint8Array;
}

// 由去重前的节点字节序列构建节点池：按 Keccak-256 摘要去重，
// 并对每个节点做一次严格 RLP 解码与规范重编码比对（解码结果缓存供各条路径复用）。
function buildPool(nodeBytesList) {
  const entries = [];
  const byHash = new Map();
  let submittedCount = 0;
  for (const bytes of nodeBytesList) {
    submittedCount += 1;
    const hashHex = toHex(keccak256(bytes));
    if (byHash.has(hashHex)) continue; // 同一节点重复粘贴：去重，只保留一份
    const entry = {
      index: entries.length,
      bytes,
      hashHex,
      rlpSize: bytes.length,
      decoded: null,
      decodeError: null,
    };
    try {
      const raw = rlp.decodeCanonical(bytes);
      const reencoded = rlp.encode(raw);
      if (!equalBytes(reencoded, bytes)) {
        entry.decodeError = { code: 'RLP_NONCANONICAL', detail: '规范重编码与原字节不一致（非规范编码）' };
      } else {
        entry.decoded = raw;
      }
    } catch (e) {
      const noncanon = /非规范|前导零|边界不一致|多余字节/.test(e.message);
      entry.decodeError = {
        code: noncanon ? 'RLP_NONCANONICAL' : 'RLP_INVALID',
        detail: noncanon ? `非规范编码——${e.message}` : `解码失败（截断/结构错误）——${e.message}`,
      };
    }
    entries.push(entry);
    byHash.set(hashHex, entry);
  }
  return { entries, byHash, submittedCount };
}

function verifyFromPool(rootHash, keyNibbles, pool) {
  const layers = []; // 已成功核验并回放的层（含失败前保留的路径证据）
  const consumed = [];
  const reached = []; // 本路径实际抵达的池节点序号

  const invalid = (code, reason, firstFailedLayer) => ({
    status: 'invalid',
    authorized: false,
    value: null,
    code,
    reason,
    firstFailedLayer,
    layers,
    consumedPath: nibblesToHex(consumed),
    reached,
  });

  if (!(rootHash instanceof Uint8Array) || rootHash.length !== 32) {
    return invalid('BAD_ROOT', '根哈希必须为 32 字节', 0);
  }
  if (!Array.isArray(keyNibbles) || keyNibbles.some((n) => !Number.isInteger(n) || n < 0 || n > 15)) {
    return invalid('BAD_KEY', '十六进制指令标识必须为十六进制半字节序列（字符 0..f，可为奇数长度）', 0);
  }

  // 根承诺：由 32 字节根哈希在池中定位根节点（而非信任池中的第一个节点）。
  const rootHex = toHex(rootHash);
  let entry = pool.byHash.get(rootHex);
  if (!entry) {
    return invalid(
      'ROOT_MISMATCH',
      `父子引用不符：节点池中没有任何节点的 Keccak-256 摘要等于根哈希 0x${rootHex}`,
      1
    );
  }
  reached.push(entry.index);

  let nodeRef = { mode: 'root-commitment' };
  let remainder = keyNibbles.slice();

  // 解析子引用：内嵌列表直接采用；32 字节散列必须在节点池中命中。
  // 命中即把该池节点记为本路径“已抵达”（即使其 RLP 随后被判定非法，
  // 它也确实被父节点引用所指向，不应再被统计为冗余证据）。
  const resolveChild = (ref) => {
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
    const target = pool.byHash.get(toHex(ref));
    if (!target) {
      return { errorCode: 'PATH_INCOMPLETE', error: `路径残缺——散列引用 0x${toHex(ref)} 在节点池中缺少对应节点` };
    }
    reached.push(target.index);
    return { entry: target, embedded: false };
  };

  for (;;) {
    const layerNo = layers.length + 1;

    // 池节点的 RLP 解码问题在“实际抵达该节点的这一层”暴露：
    // 坏节点只令经过它的那条指令失败，不影响同批其他指令。
    if (nodeRef.mode !== 'embedded-node' && entry.decodeError) {
      return invalid(entry.decodeError.code, `第 ${layerNo} 层：RLP ${entry.decodeError.detail}`, layerNo);
    }
    const node = nodeRef.mode === 'embedded-node' ? nodeRef.raw : entry.decoded;

    if (!Array.isArray(node) || (node.length !== 2 && node.length !== 17)) {
      return invalid('NODE_MALFORMED', `第 ${layerNo} 层：节点既非 2 项（叶/扩展）也非 17 项（分支）`, layerNo);
    }

    // 2 项节点：以 HP 终止标志区分叶节点与扩展节点。
    if (node.length === 2) {
      const [pathBytes, second] = node;
      if (!isBytes(pathBytes)) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：路径字段必须是字节串`, layerNo);
      }
      let hpDec;
      try {
        hpDec = hp.decode(pathBytes);
      } catch (e) {
        return invalid('HP_INVALID', `第 ${layerNo} 层：十六进制前缀错误——${e.message}`, layerNo);
      }

      // ---------------- 叶节点 ----------------
      if (hpDec.terminator) {
        if (!isBytes(second)) {
          return invalid('NODE_MALFORMED', `第 ${layerNo} 层：叶节点值必须是字节串`, layerNo);
        }
        const path = hpDec.nibbles;
        if (remainder.length !== path.length || path.some((n, i) => n !== remainder[i])) {
          return invalid(
            'PATH_MISMATCH',
            `第 ${layerNo} 层：路径残缺/偏离——叶路径 ${nibblesToHex(path)} 与剩余半字节 ${nibblesToHex(remainder)} 不一致`,
            layerNo
          );
        }
        const hashHex = nodeRef.mode === 'embedded-node' ? toHex(keccak256(rlp.encode(node))) : entry.hashHex;
        const rlpSize = nodeRef.mode === 'embedded-node' ? rlp.encode(node).length : entry.rlpSize;
        for (const n of path) consumed.push(n);
        layers.push({
          layer: layerNo,
          kind: 'leaf',
          reference: nodeRef.mode,
          embeddedInLayer: nodeRef.parentLayer ?? null,
          poolIndex: nodeRef.mode === 'embedded-node' ? null : entry.index,
          nodeHash: hashHex,
          rlpSize,
          hpPrefix: toHex(pathBytes),
          consumedNibbles: nibblesToHex(path),
          cumulativePath: nibblesToHex(consumed),
          value: toHex(second),
        });
        // 池是无序集合，叶之后“多余”的池节点不属于本路径，统一由聚合层列为冗余证据。
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
          reached,
        };
      }

      // ---------------- 扩展节点 ----------------
      if (hpDec.nibbles.length === 0) {
        return invalid('HP_INVALID', `第 ${layerNo} 层：十六进制前缀错误——扩展节点路径为空`, layerNo);
      }
      const path = hpDec.nibbles;
      if (remainder.length < path.length || path.some((n, i) => n !== remainder[i])) {
        return invalid(
          'PATH_MISMATCH',
          `第 ${layerNo} 层：路径残缺/偏离——扩展路径 ${nibblesToHex(path)} 与剩余半字节 ${nibblesToHex(remainder)} 不匹配`,
          layerNo
        );
      }

      const hashHex = nodeRef.mode === 'embedded-node' ? toHex(keccak256(rlp.encode(node))) : entry.hashHex;
      const rlpSize = nodeRef.mode === 'embedded-node' ? rlp.encode(node).length : entry.rlpSize;
      const child = resolveChild(second);
      const childRefMode = Array.isArray(second) ? 'embedded-node' : 'hash-32';
      layers.push({
        layer: layerNo,
        kind: 'extension',
        reference: nodeRef.mode,
        embeddedInLayer: nodeRef.parentLayer ?? null,
        poolIndex: nodeRef.mode === 'embedded-node' ? null : entry.index,
        nodeHash: hashHex,
        rlpSize,
        hpPrefix: toHex(pathBytes),
        consumedNibbles: nibblesToHex(path),
        cumulativePath: nibblesToHex(consumed.concat(path)),
        childReference: childRefMode,
        childHash: childRefMode === 'hash-32' ? toHex(second) : null,
      });
      if (child.errorCode) {
        const atLayer = child.errorCode === 'BAD_REF' ? layerNo : layerNo + 1;
        return invalid(child.errorCode, `第 ${atLayer} 层：${child.error}`, atLayer);
      }
      for (const n of path) consumed.push(n);
      if (child.embedded) {
        nodeRef = { mode: 'embedded-node', raw: child.raw, parentLayer: layerNo };
      } else {
        entry = child.entry;
        nodeRef = { mode: 'hash-32' };
      }
      remainder = remainder.slice(path.length);
      continue;
    }

    // ---------------- 分支节点（17 项）----------------
    for (let i = 0; i < 17; i++) {
      const item = node[i];
      if (!(isBytes(item) || Array.isArray(item))) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：分支槽 ${i} 类型非法`, layerNo);
      }
      if (i < 16 && isBytes(item) && item.length !== 0 && item.length !== 32) {
        return invalid('BAD_REF', `第 ${layerNo} 层：分支槽 ${i} 的字节串长度为 ${item.length}，只允许空串或 32 字节散列`, layerNo);
      }
      if (i === 16 && Array.isArray(item)) {
        return invalid('NODE_MALFORMED', `第 ${layerNo} 层：分支值槽（16）必须为字节串或空`, layerNo);
      }
    }

    if (remainder.length === 0) {
      const v = node[16];
      if (!isBytes(v) || v.length === 0) {
        return invalid('PATH_INCOMPLETE', `第 ${layerNo} 层：路径残缺——半字节已耗尽但分支值槽为空`, layerNo);
      }
      const hashHex = nodeRef.mode === 'embedded-node' ? toHex(keccak256(rlp.encode(node))) : entry.hashHex;
      const rlpSize = nodeRef.mode === 'embedded-node' ? rlp.encode(node).length : entry.rlpSize;
      layers.push({
        layer: layerNo,
        kind: 'branch-value',
        reference: nodeRef.mode,
        embeddedInLayer: nodeRef.parentLayer ?? null,
        poolIndex: nodeRef.mode === 'embedded-node' ? null : entry.index,
        nodeHash: hashHex,
        rlpSize,
        slot: 16,
        consumedNibbles: '',
        cumulativePath: nibblesToHex(consumed),
        value: toHex(v),
      });
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
        reached,
      };
    }

    const idx = remainder[0];
    const slot = node[idx];
    if (isBytes(slot) && slot.length === 0) {
      return invalid('PATH_INCOMPLETE', `第 ${layerNo} 层：路径残缺——分支槽 ${idx.toString(16)} 为空`, layerNo);
    }
    const hashHex = nodeRef.mode === 'embedded-node' ? toHex(keccak256(rlp.encode(node))) : entry.hashHex;
    const rlpSize = nodeRef.mode === 'embedded-node' ? rlp.encode(node).length : entry.rlpSize;
    const child = resolveChild(slot);
    const childRefMode = Array.isArray(slot) ? 'embedded-node' : 'hash-32';
    layers.push({
      layer: layerNo,
      kind: 'branch',
      reference: nodeRef.mode,
      embeddedInLayer: nodeRef.parentLayer ?? null,
      poolIndex: nodeRef.mode === 'embedded-node' ? null : entry.index,
      nodeHash: hashHex,
      rlpSize,
      slot: idx,
      consumedNibbles: idx.toString(16),
      cumulativePath: nibblesToHex(consumed.concat([idx])),
      childReference: childRefMode,
      childHash: childRefMode === 'hash-32' ? toHex(slot) : null,
    });
    if (child.errorCode) {
      const atLayer = child.errorCode === 'BAD_REF' ? layerNo : layerNo + 1;
      return invalid(child.errorCode, `第 ${atLayer} 层：${child.error}`, atLayer);
    }
    consumed.push(idx);
    if (child.embedded) {
      nodeRef = { mode: 'embedded-node', raw: child.raw, parentLayer: layerNo };
    } else {
      entry = child.entry;
      nodeRef = { mode: 'hash-32' };
    }
    remainder = remainder.slice(1);
  }
}

module.exports = { buildPool, verifyFromPool };
