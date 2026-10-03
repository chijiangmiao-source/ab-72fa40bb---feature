'use strict';
// 离线 MPT 存在性证明核验内核（浏览器与 Node 共用，零依赖）。
//
// 输入：
//   rootHash      Uint8Array(32)        提交的状态根
//   keyNibbles    number[]              十六进制指令标识的半字节路径
//   proofNodes    Uint8Array[]          按根到叶排序的 RLP 编码节点
// 输出（结构化结果，供结果页逐层回放）：
//   { status: 'authorized' | 'unauthorized' | 'invalid',
//     authorized: boolean, value: hex|null,
//     layers: [...], consumedPath,
//     firstFailedLayer: number|null, code, reason }
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

function verifyProof(rootHash, keyNibbles, proofNodes) {
  const layers = []; // 已成功核验并回放的层
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
    const nodeBytes = proofNodes[i];
    if (!isBytes(nodeBytes)) {
      return invalid('BAD_NODE_BYTES', `第 ${i + 1} 层：节点不是字节串`, i + 1, layers, consumed);
    }
    let raw;
    try {
      raw = rlp.decodeCanonical(nodeBytes);
    } catch (e) {
      const noncanon = /非规范|前导零|边界不一致|多余字节/.test(e.message);
      return invalid(
        noncanon ? 'RLP_NONCANONICAL' : 'RLP_INVALID',
        `第 ${i + 1} 层：RLP ${noncanon ? '非规范编码' : '解码失败（截断/结构错误）'}——${e.message}`,
        i + 1,
        layers,
        consumed
      );
    }
    let reencoded;
    try {
      reencoded = rlp.encode(raw);
    } catch (e) {
      return invalid('RLP_INVALID', `第 ${i + 1} 层：节点结构无法重新编码——${e.message}`, i + 1, layers, consumed);
    }
    if (!equalBytes(reencoded, nodeBytes)) {
      return invalid('RLP_NONCANONICAL', `第 ${i + 1} 层：RLP 非规范编码（规范重编码与原字节不一致）`, i + 1, layers, consumed);
    }
    decoded.push(raw);
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
  let node = decoded[0];
  let nodeRef = { mode: 'root-commitment' }; // 当前节点的引用方式
  let remainder = keyNibbles.slice();

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
    if (proofIdx >= decoded.length) {
      return { errorCode: 'PATH_INCOMPLETE', error: `路径残缺——散列引用 0x${toHex(ref)} 缺少对应证明节点` };
    }
    const nextBytes = proofNodes[proofIdx];
    if (!equalBytes(keccak256(nextBytes), ref)) {
      return {
        errorCode: 'REF_MISMATCH',
        error: `父子引用不符——子节点散列 0x${toHex(keccak256(nextBytes))} 不等于父节点引用 0x${toHex(ref)}`,
      };
    }
    const raw = decoded[proofIdx];
    proofIdx += 1;
    return { raw, embedded: false };
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
        if (proofIdx < decoded.length) {
          return invalid(
            'TAIL_DUPLICATE',
            `叶节点之后仍有 ${decoded.length - proofIdx} 个未消费节点（重复尾节点/冗余证据）`,
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
      const child = resolveChild(second);
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
      if (proofIdx < decoded.length) {
        return invalid('TAIL_DUPLICATE', `第 ${layerNo + 1} 层：抵达终值后仍有未消费的重复尾节点`, layerNo + 1, layers, consumed);
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
    const child = resolveChild(slot);
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
    nodeRef = child.embedded ? { mode: 'embedded-node', parentLayer: layerNo } : { mode: 'hash-32' };
    remainder = remainder.slice(1);
  }
}

module.exports = { verifyProof };
