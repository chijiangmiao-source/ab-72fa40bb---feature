'use strict';
// 批量复核：同一离线授权快照（一个 32 字节根哈希 + 一个去重 RLP 节点池）下，
// 为 2..8 条十六进制指令标识分别独立核验，并聚合跨路径的节点复用与冗余证据。
//
// 每条指令各自从根出发独立追随分支/扩展/叶引用；单条指令遇到
// 缺失引用、非规范 RLP 或路径不符时，只产出该条的 invalid 结论（旧成功结论只对该条清除），
// 不影响同批其余指令。节点池中未被任何目标路径消费的节点列为冗余证据。
const { buildPool, verifyFromPool } = require('./pool-verifier');
const { toHex } = require('./hexutil');

function verifyBatch(rootHash, keyHexesRaw, proofNodes) {
  const keyHexes = (keyHexesRaw || []).map((k) => (k || '').replace(/^0[xX]/, '').toLowerCase());
  const pool = buildPool(proofNodes);

  const results = keyHexes.map((keyHex, i) => {
    const nibbles = Array.from(keyHex, (c) => parseInt(c, 16));
    const result = verifyFromPool(rootHash, nibbles, pool);
    return { index: i, keyHex, result };
  });

  // 池节点消费统计：被哪些指令路径抵达、各经过几次。
  const consumers = pool.entries.map(() => ({ uses: [] }));
  for (const { keyHex, result } of results) {
    for (const poolIndex of result.reached || []) {
      consumers[poolIndex].uses.push(keyHex);
    }
  }

  // 共享节点：被至少两条不同指令路径消费。reuseCount 为跨全部路径的总抵达次数。
  const shared = [];
  for (const entry of pool.entries) {
    const uses = consumers[entry.index].uses;
    const commands = [...new Set(uses)];
    if (commands.length >= 2) {
      shared.push({
        poolIndex: entry.index,
        nodeHash: entry.hashHex,
        rlpSize: entry.rlpSize,
        reuseCount: uses.length,
        commands,
      });
    }
  }

  // 冗余证据：没有任何目标路径抵达的池节点（含无法解码的坏节点——坏节点只有被引用抵达才会致某条指令失败）。
  const redundant = [];
  for (const entry of pool.entries) {
    if (consumers[entry.index].uses.length === 0) {
      redundant.push({
        poolIndex: entry.index,
        nodeHash: entry.hashHex,
        rlpSize: entry.rlpSize,
        decodeErrorCode: entry.decodeError ? entry.decodeError.code : null,
      });
    }
  }

  // 每条指令附带其路径上共享节点的复用视图，并逐层标注。
  for (const { keyHex, result } of results) {
    result.sharedNodes = shared
      .filter((s) => result.reached.includes(s.poolIndex))
      .map((s) => ({
        poolIndex: s.poolIndex,
        nodeHash: s.nodeHash,
        reuseCount: s.reuseCount,
        commands: s.commands,
        otherCommands: s.commands.filter((k) => k !== keyHex),
      }));
    for (const layer of result.layers) {
      if (layer.poolIndex == null) {
        layer.shared = null;
        continue;
      }
      const uses = consumers[layer.poolIndex].uses;
      const commands = [...new Set(uses)];
      layer.shared = commands.length >= 2
        ? { reuseCount: uses.length, commands, otherCommands: commands.filter((k) => k !== keyHex) }
        : null;
    }
  }

  return {
    rootHashHex: toHex(rootHash),
    submittedNodeCount: pool.submittedCount,
    poolNodeCount: pool.entries.length,
    duplicateNodeCount: pool.submittedCount - pool.entries.length,
    results,
    shared,
    redundant,
  };
}

module.exports = { verifyBatch, buildPool };
