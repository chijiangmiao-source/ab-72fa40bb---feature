'use strict';
// 标准 Merkle Patricia Trie 构建器（用于生成离线快照与测试夹具）。
// 规则与以太坊一致：序列化后长度 < 32 字节的子节点以内嵌 RLP 列表存放，否则存放 32 字节 Keccak 散列。
const { keccak256 } = require('./keccak');
const rlp = require('./rlp');
const hp = require('./hexpath');

function leaf(path, value) {
  return { t: 'l', path, value: value instanceof Uint8Array ? value : Uint8Array.of(...value) };
}
function ext(path, child) {
  return { t: 'e', path, child };
}
function branch() {
  return { t: 'b', slots: new Array(17).fill(null) };
}

function commonPrefix(a, b) {
  let i = 0;
  const n = Math.min(a.length, b.length);
  while (i < n && a[i] === b[i]) i++;
  return i;
}

function insert(node, key, value) {
  if (!node) return leaf(key, value);

  if (node.t === 'l') {
    const c = commonPrefix(node.path, key);
    if (c === node.path.length && c === key.length) return leaf(key, value); // 同键覆写
    const br = branch();
    if (c === node.path.length) {
      br.slots[16] = { valueNode: node.value }; // 旧值落入值槽
      br.slots[key[c]] = leaf(key.slice(c + 1), value);
      return c === 0 ? br : ext(node.path.slice(0, c), br);
    }
    br.slots[node.path[c]] = leaf(node.path.slice(c + 1), node.value);
    if (c === key.length) br.slots[16] = { valueNode: value };
    else br.slots[key[c]] = leaf(key.slice(c + 1), value);
    return c === 0 ? br : ext(key.slice(0, c), br);
  }

  if (node.t === 'e') {
    const c = commonPrefix(node.path, key);
    if (c === node.path.length) {
      return ext(node.path, insert(node.child, key.slice(c), value));
    }
    const br = branch();
    const oldRest = node.path.slice(c + 1);
    br.slots[node.path[c]] = oldRest.length === 0 ? node.child : ext(oldRest, node.child);
    if (c === key.length) br.slots[16] = { valueNode: value };
    else br.slots[key[c]] = leaf(key.slice(c + 1), value);
    return c === 0 ? br : ext(key.slice(0, c), br);
  }

  // branch
  if (key.length === 0) {
    node.slots[16] = { valueNode: value };
  } else {
    node.slots[key[0]] = insert(node.slots[key[0]], key.slice(1), value);
  }
  return node;
}

// 提交：填充 encoded/hash/embedded，并登记 hashHex -> node。
function commit(node, table) {
  let raw;
  if (node.t === 'l') {
    raw = [hp.encode(node.path, true), node.value];
  } else if (node.t === 'e') {
    raw = [hp.encode(node.path, false), commitRef(node.child, table)];
  } else {
    raw = node.slots.map((slot, i) => {
      if (!slot) return new Uint8Array(0);
      if (slot.valueNode !== undefined) return slot.valueNode; // 值槽
      return commitRef(slot, table);
    });
  }
  node.encoded = rlp.encode(raw);
  node.hash = keccak256(node.encoded);
  table.set(Buffer.from(node.hash).toString('hex'), node);
  return raw;
}

function commitRef(child, table) {
  const childRaw = commit(child, table);
  if (child.encoded.length < 32) {
    child.embedded = true;
    return childRaw; // 内嵌 RLP 列表
  }
  child.embedded = false;
  return child.hash; // 32 字节散列引用
}

// 按根到叶收集证明：仅列出根节点与经 32 字节散列引用的节点；
// 内嵌节点已包含在父节点 RLP 负载中，不单独列出（核验端从父节点解码递归进入）。
function prove(root, key) {
  const nodes = [];
  const walk = (cur, k, isRoot) => {
    if (isRoot || !cur.embedded) nodes.push(cur.encoded);
    if (cur.t === 'l') {
      if (commonPrefix(cur.path, k) !== cur.path.length || cur.path.length !== k.length) {
        throw new Error('证明生成失败：键不存在于树中');
      }
      return;
    }
    if (cur.t === 'e') {
      if (commonPrefix(cur.path, k) !== cur.path.length) {
        throw new Error('证明生成失败：扩展路径不匹配');
      }
      walk(cur.child, k.slice(cur.path.length), false);
      return;
    }
    if (k.length === 0) {
      const v = cur.slots[16];
      if (!v || v.valueNode === undefined) throw new Error('证明生成失败：值槽为空');
      return;
    }
    const next = cur.slots[k[0]];
    if (!next) throw new Error('证明生成失败：分支断链');
    walk(next, k.slice(1), false);
  };
  walk(root, key, true);
  return nodes;
}

class Trie {
  constructor() {
    this.root = null;
    this.table = new Map();
    this.committed = false;
  }

  put(keyNibbles, value) {
    this.committed = false;
    this.root = insert(this.root, keyNibbles, value instanceof Uint8Array ? value : Uint8Array.of(...value));
    return this;
  }

  // 返回 { rootHash: Uint8Array(32) }
  commit() {
    this.table = new Map();
    if (!this.root) {
      this.rootHash = keccak256(rlp.encode(new Uint8Array(0)));
    } else {
      commit(this.root, this.table);
      this.rootHash = this.root.hash;
    }
    this.committed = true;
    return this.rootHash;
  }

  proveKey(keyNibbles) {
    if (!this.committed) this.commit();
    if (!this.root) throw new Error('空树无法生成证明');
    return prove(this.root, keyNibbles);
  }
}

module.exports = { Trie, commonPrefix };
