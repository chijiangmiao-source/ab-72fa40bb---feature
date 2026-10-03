'use strict';
// 内置离线示例快照：构造一棵覆盖 扩展/分支/叶、内嵌节点与 32 字节散列引用的 MPT。
// 供入口页“一键载入示例”与验收冒烟使用；真实使用时审查员导入自己的离线快照。
const { Trie } = require('./trie');
const { toHex, bytesToNibbles } = require('./hexutil');

function buildSnapshots() {
  const trie = new Trie();
  const put = (keyHex, ...value) => trie.put(bytesToNibbles(Buffer.from(keyHex, 'hex')), Uint8Array.of(...value));

  // 深前缀族：迫使上层出现扩展节点与散列引用
  put('0123456789abcdef0123', 0x01); // 有效授权目标
  put('0123456789abcdef0124', 0x00); // 同构兄弟键：叶值 00 -> 未授权
  put('0123456789abcdef0abc', 0x01);
  put('0123456789abdddddddd', 0x02);
  // 另一前缀族
  put('fedcba9876543210abcd', 0x01);
  put('fedcba9876543210abce', 0x01);
  // 短键：迫使分支槽下出现 < 32 字节的内嵌叶节点
  put('a1', 0x00);
  put('a2', 0x01);

  const rootHash = trie.commit();

  const proofFor = (keyHex) => trie.proveKey(bytesToNibbles(Buffer.from(keyHex, 'hex')));

  return {
    trie,
    rootHash,
    rootHashHex: toHex(rootHash),
    keys: {
      authorized: '0123456789abcdef0123',
      unauthorized: '0123456789abcdef0124',
      otherAuthorized: 'a2',
      shortUnauthorized: 'a1',
    },
    proofFor,
  };
}

// 批量复核示例：多指令共享一个去重节点池。
//   - 0123456789abcdef0123 已授权（01）、……0124 未授权（00）：共享深前缀族共同节点；
//   - a2 已授权（短键，经过内嵌叶）；
//   - 0123456789abcdef0129 不存在：该条判无效（路径失败），同批其余结论不受影响；
//   - 额外并入 fedc…abcd 证明的独有节点但不查询它：形成冗余证据；
//   - 故意打乱池顺序并重复粘贴根节点，展示“无序提交 + 去重”。
function buildBatchSample() {
  const snap = buildSnapshots();
  const queried = [
    snap.keys.authorized,
    snap.keys.unauthorized,
    snap.keys.otherAuthorized,
    '0123456789abcdef0129',
  ];
  const collected = [];
  const addProof = (keyHex) => {
    for (const node of snap.proofFor(keyHex)) collected.push(toHex(node));
  };
  queried.slice(0, 3).forEach(addProof);
  addProof('fedcba9876543210abcd'); // 独有节点将成为冗余证据

  const { keccak256 } = require('./keccak');
  const unique = [];
  const seen = new Set();
  for (const hex of collected) {
    const h = toHex(keccak256(Buffer.from(hex, 'hex')));
    if (!seen.has(h)) {
      seen.add(h);
      unique.push(hex);
    }
  }
  // 确定性乱序：整体右移三位，避免依赖随机数。
  const shuffled = unique.slice(3).concat(unique.slice(0, 3));
  // 重复粘贴一个共同节点（根），验证服务端去重。
  shuffled.push(shuffled[0]);

  return {
    rootHash: snap.rootHashHex,
    keyHexes: queried,
    proofNodes: shuffled,
  };
}

module.exports = { buildSnapshots, buildBatchSample };
