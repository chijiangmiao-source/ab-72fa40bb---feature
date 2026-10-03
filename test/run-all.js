'use strict';
// 验收测试总入口：按「有效授权 → 篡改子节点引用 → 非规范 RLP」三大场景，
// 穿插运行 证明内核校验 / 结果页构建检查 / API 与 HTTP（含健康端点）冒烟。
const { createHarness, assert } = require('./harness');
const { buildSnapshots } = require('./fixtures');
const { verifyProof, verifyProofFromPool, verifyBatch, dedupePool } = require('../src/verifier');
const { handleVerify, handleVerifyBatch, parseProofNodes, parseKeyHexes } = require('../src/verify-api');
const { buildResultPage, buildBatchPage, buildIndexPage } = require('../src/page');
const { createServer } = require('../src/server');
const { keccak256 } = require('../src/keccak');
const rlp = require('../src/rlp');
const hp = require('../src/hexpath');
const { toHex, fromHex, bytesToNibbles, equalBytes } = require('../src/hexutil');

const B = (hex) => fromHex(hex);
const U = (...xs) => Uint8Array.of(...xs);

// 手工 RLP 列表封装（用于构造含非规范内嵌项的测试字节）。
function concatRaw(parts) {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}
function rlpLenPrefix(payloadLen, base) {
  if (payloadLen < 56) return Uint8Array.of(base + payloadLen);
  const bytes = [];
  let x = payloadLen;
  while (x > 0) {
    bytes.push(x & 0xff);
    x = Math.floor(x / 256);
  }
  bytes.reverse();
  return Uint8Array.of(base + 55 + bytes.length, ...bytes);
}

async function main() {
  const h = createHarness();
  const { test, suite, assert: a } = h;

  const snap = buildSnapshots();
  const keyAuth = snap.keys.authorized;
  const keyNo = snap.keys.unauthorized;
  const proofAuth = snap.proofFor(keyAuth);
  const proofNo = snap.proofFor(keyNo);

  // ---------- 原语向量 ----------
  await suite('原语：Keccak-256 / RLP / HP').run(async () => {
    test('Keccak-256 空串与 "abc" 标准向量', () => {
      a.equal(toHex(keccak256(U())), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
      a.equal(toHex(keccak256(Buffer.from('abc'))), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
    });

    test('RLP 标准编码向量', () => {
      a.equal(toHex(rlp.encode(B('646f67'))), '83646f67');
      a.equal(toHex(rlp.encode(U())), '80');
      a.equal(toHex(rlp.encode([])), 'c0');
      a.equal(toHex(rlp.encode(U(0))), '00');
    });

    test('RLP 拒绝非规范/截断/前导零/尾部多余字节', () => {
      // 截断/结构错误：宽容与严格两种解码都必须拒绝
      const broken = [
        ['8261', '短串截断'],
        ['c1', '列表截断'],
        ['f838' + 'c0'.repeat(0x37), '长列表截断（声明 56 字节负载，实给 55）'],
        ['8000', '完整项后多余字节'],
      ];
      for (const [hex, label] of broken) {
        a.throws(() => rlp.decode(B(hex)), undefined, label);
        a.throws(() => rlp.decodeCanonical(B(hex)), undefined, label + '（严格）');
      }
      // 纯非规范形式：宽容解码接受、严格解码拒绝
      const noncanon = [
        ['8100', '单字节 0x00 的长形式'],
        ['817f', '单字节 0x7f 的长形式'],
        ['b800', '空串误用长形式'],
        ['b837' + '61'.repeat(0x37), '55 字节误用长形式'],
        ['b90038' + '61'.repeat(0x38), '长度前导零'],
      ];
      for (const [hex, label] of noncanon) {
        a.doesNotThrow(() => rlp.decode(B(hex)), label + ' 可被宽容解码');
        a.throws(() => rlp.decodeCanonical(B(hex)), undefined, label);
      }
      // 非规范形式重编码后字节必然不同
      const nc = rlp.decode(B('8100'));
      a.notEqual(toHex(rlp.encode(nc)), '8100');
    });

    test('HP 编解码往返与非法前缀拒绝', () => {
      for (const [nibs, term] of [[[1, 2, 3], true], [[0xa, 0xb], false], [[0xf], true], [[], true]]) {
        const d = hp.decode(hp.encode(nibs, term));
        a.deepEqual(d.nibbles, nibs);
        a.equal(d.terminator, term);
      }
      a.throws(() => hp.decode(B('40')), /高两位/, '高两位置位');
      a.throws(() => hp.decode(B('0fab')), /填充半字节/, '偶数路径低半字节非零');
      a.throws(() => hp.decode(U()), /为空/, '空前缀');
    });
  });

  // 预先启动一台临时 HTTP 服务，供三大场景穿插冒烟（单次初始化，避免并发竞态）。
  let server;
  let baseUrl;
  let starting;
  const http = async (path, opts) => {
    if (!starting) {
      starting = (async () => {
        server = createServer();
        await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
        baseUrl = `http://127.0.0.1:${server.address().port}`;
      })();
    }
    await starting;
    return fetch(baseUrl + path, opts);
  };

  const postVerify = async (rootHash, keyHex, nodesText) =>
    http('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rootHash, keyHex, proofNodes: nodesText }),
    });

  const postVerifyBatch = async (rootHash, keyHexes, poolText) =>
    http('/api/verify-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rootHash, keyHexes, proofNodes: poolText }),
    });

  // ========== 场景一：有效授权（叶值 01）==========
  await suite('场景一：有效授权（证明内核 → 页面 → API → HTTP 穿插）').run(async () => {
    test('证明内核：长键证明状态为 authorized，逐层消费完整路径', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      a.equal(res.status, 'authorized');
      a.equal(res.authorized, true);
      a.equal(res.value, '01');
      a.equal(res.firstFailedLayer, null);
      a.equal(res.consumedPath, keyAuth);
      a.ok(res.layers.length >= 3, '应回放多层（含扩展/分支/叶）');
      const leaf = res.layers[res.layers.length - 1];
      a.equal(leaf.kind, 'leaf');
      a.equal(leaf.value, '01');
      // 每层必须给出节点摘要与引用方式
      for (const layer of res.layers) {
        a.match(layer.nodeHash, /^[0-9a-f]{64}$/);
        a.ok(['root-commitment', 'hash-32', 'embedded-node'].includes(layer.reference));
      }
      // 至少出现一次内嵌节点引用与一次 32 字节散列引用
      a.ok(res.layers.some((l) => l.childReference === 'embedded-node' || l.reference === 'embedded-node'));
      a.ok(res.layers.some((l) => l.childReference === 'hash-32' || l.reference === 'root-commitment'));
    });

    test('证明内核：短键 + 内嵌叶同样授权', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(snap.keys.otherAuthorized)), snap.proofFor(snap.keys.otherAuthorized));
      a.equal(res.status, 'authorized');
      a.equal(res.consumedPath, 'a2');
    });

    test('页面构建：结果页显示“已授权”并逐层列出摘要/路径/引用方式', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyAuth, nodeCount: proofAuth.length });
      a.match(page, /<title>离线指令授权快照复核结果<\/title>/);
      a.match(page, /已授权/);
      a.match(page, /叶值为 <code>0x01<\/code>/);
      a.match(page, new RegExp(snap.rootHashHex));
      a.match(page, new RegExp(keyAuth));
      a.match(page, /内嵌节点/);
      a.match(page, /32 字节散列引用|根承诺/);
      a.match(page, /累计已消费路径/);
      a.equal(page.includes('证明无效'), false);
    });

    test('API：合法 JSON 入参返回 200 与 result+page', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: keyAuth,
        proofNodes: proofAuth.map((p) => toHex(p)).join('\n'),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.status, 'authorized');
      a.match(out.page, /已授权/);
    });

    test('API：JSON 数组形式的节点列表同样接受', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: snap.keys.otherAuthorized,
        proofNodes: snap.proofFor(snap.keys.otherAuthorized).map((p) => '0x' + toHex(p)),
      });
      a.equal(out.result.status, 'authorized');
    });

    test('API：指令标识支持 0x 前缀，非十六进制字符被 400 拒绝', () => {
      const out = handleVerify({
        rootHash: '0x' + snap.rootHashHex,
        keyHex: '0x' + snap.keys.otherAuthorized,
        proofNodes: snap.proofFor(snap.keys.otherAuthorized).map((p) => toHex(p)),
      });
      a.equal(out.result.status, 'authorized');
      const bad = handleVerify({ rootHash: snap.rootHashHex, keyHex: 'a2g', proofNodes: '80' });
      a.equal(bad.httpStatus, 400);
      a.match(bad.error, /十六进制/);
    });

    test('HTTP 冒烟：健康端点 200 ok', async () => {
      const res = await http('/healthz');
      a.equal(res.status, 200);
      a.deepEqual(await res.json(), { status: 'ok', service: 'offline-instruction-auth-review' });
    });

    test('HTTP 冒烟：静态入口页可访问且含表单', async () => {
      const res = await http('/');
      a.equal(res.status, 200);
      a.match(res.headers.get('content-type'), /text\/html/);
      const html = await res.text();
      a.match(html, /<title>离线指令授权快照复核<\/title>/);
      a.match(html, /name="rootHash"/);
      a.match(html, /name="keyHex"/);
      a.match(html, /name="proofNodes"/);
    });

    test('HTTP 冒烟：POST 有效授权证明返回已授权页面', async () => {
      const res = await postVerify(snap.rootHashHex, keyAuth, proofAuth.map((p) => toHex(p)).join('\n'));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'authorized');
      a.match(data.page, /已授权/);
    });
  });

  // ========== 场景二：篡改子节点引用 ==========
  await suite('场景二：篡改子节点引用（REF_MISMATCH，内核 → 页面 → API → HTTP 穿插）').run(async () => {
    // 翻转第 2 个证明节点（扩展节点）散列负载中的一个字节，保持 RLP 仍可解码。
    const tampered = proofAuth.map((p) => Uint8Array.from(p));
    tampered[1][tampered[1].length - 1] ^= 0x01;

    test('证明内核：首个失败层为第 2 层且无成功结论', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), tampered);
      a.equal(res.status, 'invalid');
      a.equal(res.code, 'REF_MISMATCH');
      a.equal(res.firstFailedLayer, 2);
      a.equal(res.value, null);
      a.match(res.reason, /父子引用不符/);
      // 第 1 层路径证据保留
      a.equal(res.layers.length, 1);
      a.equal(res.layers[0].kind, 'branch');
      a.equal(res.layers[0].cumulativePath, '0');
    });

    test('页面构建：无效页标明首个失败层并保留既有路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), tampered);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyAuth, nodeCount: tampered.length });
      a.match(page, /证明无效/);
      a.match(page, /首个失败层：<strong>第 2 层<\/strong>/);
      a.match(page, /父子引用不符/);
      a.match(page, /旧成功结论已清除/);
      a.equal(page.includes('已授权</span>'), false);
      a.match(page, /第 1 层/);
    });

    test('API：篡改引用产生 invalid 结果（HTTP 200 语义化结果）', () => {
      const out = handleVerify({
        rootHash: snap.rootHashHex,
        keyHex: keyAuth,
        proofNodes: tampered.map((p) => toHex(p)).join('\n'),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'REF_MISMATCH');
      a.equal(out.result.firstFailedLayer, 2);
    });

    test('HTTP 冒烟：POST 篡改证明返回 invalid 页面', async () => {
      const res = await postVerify(snap.rootHashHex, keyAuth, tampered.map((p) => toHex(p)).join('\n'));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'invalid');
      a.equal(data.result.code, 'REF_MISMATCH');
      a.match(data.page, /证明无效/);
    });

    test('证明内核：根哈希本身不符 -> ROOT_MISMATCH 第 1 层', () => {
      const wrong = Uint8Array.from(snap.rootHash);
      wrong[31] ^= 0xff;
      const res = verifyProof(wrong, bytesToNibbles(fromHex(keyAuth)), proofAuth);
      a.equal(res.code, 'ROOT_MISMATCH');
      a.equal(res.firstFailedLayer, 1);
      a.equal(res.layers.length, 0);
    });

    test('证明内核：缺失后续证明节点 -> PATH_INCOMPLETE', () => {
      const truncated = proofAuth.slice(0, 2); // 扩展节点的散列子节点无对应证明
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), truncated);
      a.equal(res.code, 'PATH_INCOMPLETE');
      a.equal(res.firstFailedLayer, 3);
      a.match(res.reason, /路径残缺/);
    });

    test('证明内核：叶后多余节点 -> TAIL_DUPLICATE 重复尾节点', () => {
      const proof = snap.proofFor(snap.keys.otherAuthorized);
      const withTail = proof.concat([Uint8Array.from(proof[proof.length - 1])]);
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(snap.keys.otherAuthorized)), withTail);
      a.equal(res.code, 'TAIL_DUPLICATE');
      a.match(res.reason, /重复尾节点/);
    });
  });

  // ========== 场景三：非规范 RLP ==========
  await suite('场景三：非规范/截断 RLP（内核 → 页面 → API → HTTP 穿插）').run(async () => {
    // 手工拼接一个“根分支 + 槽2 内嵌叶”的原始 RLP，其中叶值 0x01 被非规范地编码为 81 01。
    // 合法内嵌叶应为 c3 20 01（3 字节）；这里改写为 c4 20 8101（4 字节，单字节误用长形式）。
    // 整个节点：分支 17 项，槽 0、1 为空(80 80)，槽 2 = c4208101，其后槽 3..16 共 14 个空项。
    const makeNoncanonRoot = () => {
      const slots = [];
      for (let i = 0; i < 17; i++) slots.push(B(i === 2 ? 'c4208101' : '80'));
      const payload = concatRaw(slots);
      return Buffer.concat([Buffer.from(rlpLenPrefix(payload.length, 0xc0)), payload]);
    };

    test('证明内核：嵌套的非规范单字节编码被拒绝（RLP_NONCANONICAL）', () => {
      const bad = makeNoncanonRoot();
      const res = verifyProof(keccak256(bad), bytesToNibbles(fromHex(snap.keys.otherAuthorized)), [bad]);
      a.equal(res.status, 'invalid');
      a.equal(res.code, 'RLP_NONCANONICAL');
      a.equal(res.firstFailedLayer, 1);
      a.match(res.reason, /非规范/);
    });

    test('页面构建：非规范 RLP 页标明失败层且不含旧成功结论', () => {
      const bad = makeNoncanonRoot();
      const res = verifyProof(keccak256(bad), bytesToNibbles(fromHex(snap.keys.otherAuthorized)), [bad]);
      const page = buildResultPage(res, { rootHash: toHex(keccak256(bad)), keyHex: snap.keys.otherAuthorized, nodeCount: 1 });
      a.match(page, /证明无效/);
      a.match(page, /RLP_NONCANONICAL/);
      a.match(page, /第 1 层/);
      a.equal(page.includes('已授权</span>'), false);
    });

    test('API：非规范 RLP 返回 invalid 与可读原因', () => {
      const bad = makeNoncanonRoot();
      const out = handleVerify({
        rootHash: toHex(keccak256(bad)),
        keyHex: snap.keys.otherAuthorized,
        proofNodes: toHex(bad),
      });
      a.equal(out.result.status, 'invalid');
      a.equal(out.result.code, 'RLP_NONCANONICAL');
    });

    test('HTTP 冒烟：POST 非规范 RLP 返回 invalid 页面', async () => {
      const bad = makeNoncanonRoot();
      const res = await postVerify(toHex(keccak256(bad)), snap.keys.otherAuthorized, toHex(bad));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.status, 'invalid');
      a.equal(data.result.code, 'RLP_NONCANONICAL');
      a.match(data.page, /RLP_NONCANONICAL/);
    });

    test('证明内核：截断的节点字节被拒绝（RLP_INVALID）', () => {
      const cut = proofAuth[0].subarray(0, proofAuth[0].length - 3);
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyAuth)), [cut]);
      a.equal(res.code, 'RLP_INVALID');
      a.equal(res.firstFailedLayer, 1);
    });

    test('证明内核：非规范长度前缀（前导零）被拒绝', () => {
      const bad = B('b90038' + '61'.repeat(0x38)); // 56 字节串却带 00 前导
      const res = verifyProof(keccak256(bad), [1, 2], [bad]);
      a.equal(res.code, 'RLP_NONCANONICAL');
    });

    test('证明内核：证明为空被拒绝', () => {
      const res = verifyProof(snap.rootHash, [1], []);
      a.equal(res.code, 'EMPTY_PROOF');
    });
  });

  // ========== 未授权与其余路径/HP/引用失败 ==========
  await suite('未授权（叶值非 01）与其余失败类别').run(async () => {
    test('证明内核：完整抵达叶但值 0x00 -> unauthorized 且保留路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyNo)), proofNo);
      a.equal(res.status, 'unauthorized');
      a.equal(res.authorized, false);
      a.equal(res.value, '00');
      a.equal(res.consumedPath, keyNo);
      a.equal(res.firstFailedLayer, null);
      a.equal(res.layers[res.layers.length - 1].kind, 'leaf');
    });

    test('页面构建：未授权页明确显示“未授权”并保留路径证据', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex(keyNo)), proofNo);
      const page = buildResultPage(res, { rootHash: snap.rootHashHex, keyHex: keyNo, nodeCount: proofNo.length });
      a.match(page, /未授权/);
      a.match(page, /0x00/);
      a.match(page, new RegExp(keyNo));
      a.equal(page.includes('证明无效'), false);
    });

    test('证明内核：叶值多字节（0100）不构成启用承诺', () => {
      const raw = [hp.encode([1, 2, 3], true), B('0100')];
      const node = rlp.encode(raw);
      const res = verifyProof(keccak256(node), [1, 2, 3], [node]);
      a.equal(res.status, 'unauthorized');
      a.equal(res.value, '0100');
    });

    test('证明内核：分支值槽终结且值 01 -> authorized', () => {
      const { Trie } = require('../src/trie');
      const t = new Trie();
      t.put(bytesToNibbles(B('ab')), U(0x01));
      t.put(bytesToNibbles(B('abcdef')), U(0x01));
      t.commit();
      const proof = t.proveKey(bytesToNibbles(B('ab')));
      const res = verifyProof(t.rootHash, bytesToNibbles(B('ab')), proof);
      a.equal(res.status, 'authorized');
      a.ok(res.layers.some((l) => l.kind === 'branch-value'));
    });

    test('证明内核：查询键偏离到空槽 -> PATH_INCOMPLETE', () => {
      const res = verifyProof(snap.rootHash, bytesToNibbles(fromHex('a3')), snap.proofFor(snap.keys.otherAuthorized));
      a.equal(res.code, 'PATH_INCOMPLETE');
      // 第 1 层为根分支（消费 a），第 2 层为其内嵌分支，在槽 3 处断链。
      a.equal(res.firstFailedLayer, 2);
    });

    test('证明内核：叶路径与剩余半字节不符 -> PATH_MISMATCH', () => {
      // 用 a2 的单节点证明去查 a9：根分支槽 9 为空 -> 先命中 PATH_INCOMPLETE（合理）。
      // 手工构造单叶证明验证 PATH_MISMATCH：
      const node = rlp.encode([hp.encode([1, 2, 3], true), U(0x01)]);
      const res = verifyProof(keccak256(node), [1, 2, 9], [node]);
      a.equal(res.code, 'PATH_MISMATCH');
    });

    test('证明内核：HP 前缀高两位置位 -> HP_INVALID', () => {
      const node = rlp.encode([B('40ab'), keccak256(U(1))]);
      const res = verifyProof(keccak256(node), [0xa, 0xb], [node]);
      a.equal(res.code, 'HP_INVALID');
      a.match(res.reason, /十六进制前缀错误/);
    });

    test('证明内核：分支槽出现非空非 32 字节串 -> BAD_REF', () => {
      const branch = new Array(17).fill(U());
      branch[1] = B('0a0b'); // 10 字节非法引用
      const node = rlp.encode(branch);
      const res = verifyProof(keccak256(node), [1], [node]);
      a.equal(res.code, 'BAD_REF');
      a.equal(res.firstFailedLayer, 1);
    });

    test('证明内核：内嵌节点 ≥32 字节必须散列引用 -> BAD_REF', () => {
      const bigChild = [hp.encode([0, 1], true), B('aa'.repeat(40))]; // 编码 ≥32
      a.ok(rlp.encode(bigChild).length >= 32);
      const ext = [hp.encode([5], false), bigChild];
      const node = rlp.encode(ext);
      const res = verifyProof(keccak256(node), [5, 0, 1], [node]);
      a.equal(res.code, 'BAD_REF');
      a.match(res.reason, /32 字节散列引用/);
    });

    test('证明内核：32 字节根哈希以外的输入被拒绝', () => {
      a.equal(verifyProof(U(1, 2, 3), [1], proofAuth).code, 'BAD_ROOT');
      a.equal(verifyProof(snap.rootHash, [1, 99], proofAuth).code, 'BAD_KEY');
    });
  });

  // ========== 批量复核：去重节点池 + 多标识独立核验 ==========
  await suite('批量复核（节点池 / 独立追随 / 共享复用 / 冗余证据 / 失败隔离）').run(async () => {
    const fullPool = Array.from(new Map(snap.trie.table).values()).map((n) => n.encoded);
    const entryFor = (keyHex) => {
      try {
        return { keyHex, nibbles: Array.from(keyHex, (c) => parseInt(c, 16)), parseError: null };
      } catch (e) {
        return { keyHex, nibbles: null, parseError: e.message };
      }
    };
    const batchFor = (keyHexes, pool = fullPool) => verifyBatch(snap.rootHash, keyHexes.map(entryFor), dedupePool(pool).nodes);

    test('内核：多条标识逐条得出 authorized/unauthorized/invalid 且路径各自完整', () => {
      const batch = batchFor([keyAuth, keyNo, snap.keys.otherAuthorized, snap.keys.shortUnauthorized, 'a3']);
      a.deepEqual(batch.summary, { authorized: 2, unauthorized: 2, invalid: 1 });
      a.equal(batch.results[0].status, 'authorized');
      a.equal(batch.results[0].consumedPath, keyAuth);
      a.equal(batch.results[1].status, 'unauthorized');
      a.equal(batch.results[1].consumedPath, keyNo);
      a.equal(batch.results[2].status, 'authorized');
      a.equal(batch.results[2].consumedPath, 'a2');
      a.equal(batch.results[3].status, 'unauthorized');
      a.equal(batch.results[4].status, 'invalid');
      a.equal(batch.results[4].code, 'PATH_INCOMPLETE');
      a.equal(batch.results[4].consumedPath, 'a');
    });

    test('内核：共享前缀节点被标出复用次数与对应指令（散列引用）', () => {
      const batch = batchFor([keyAuth, keyNo]);
      const rootEntry = batch.reuse.find((e) => e.nodeHash === snap.rootHashHex);
      a.ok(rootEntry, '根节点必须出现在复用表');
      a.equal(rootEntry.reuseCount, 2);
      a.deepEqual(rootEntry.keyIndexes, [0, 1]);
      // 两条长键兄弟共享至少 4 个前缀节点（根分支 + 扩展链）
      a.ok(batch.reuse.length >= 4, `共享节点数应 >= 4，实际 ${batch.reuse.length}`);
      for (const e of batch.reuse) a.deepEqual(e.keyIndexes, [0, 1]);
    });

    test('内核：同一内嵌叶经两条路径以 embedded-node 方式复用也被标出', () => {
      // 长键家族与短键 a2 都内嵌同一 3 字节叶 RLP（hp=20,value=01），摘要相同。
      const batch = batchFor([keyAuth, snap.keys.otherAuthorized]);
      const sharedLeaf = batch.results[0].layers[batch.results[0].layers.length - 1];
      const reuseEntry = batch.reuse.find((e) => e.nodeHash === sharedLeaf.nodeHash);
      a.ok(reuseEntry, '同摘要内嵌叶应计入复用');
      a.equal(reuseEntry.reuseCount, 2);
      a.deepEqual(reuseEntry.modes, ['embedded-node', 'embedded-node']);
      // 表中同时存在独立池条目，但两条路径均经由父节点内嵌内容抵达
      a.equal(reuseEntry.inPool, true);
    });

    test('内核：短键兄弟共享的内嵌分支同样计入复用，根为散列/根形态', () => {
      const batch = batchFor([snap.keys.otherAuthorized, snap.keys.shortUnauthorized]);
      const rootEntry = batch.reuse.find((e) => e.nodeHash === snap.rootHashHex);
      a.equal(rootEntry.reuseCount, 2);
      a.deepEqual(rootEntry.modes, ['hash-32', 'hash-32']); // 根承诺归入散列/根形态
      const embeddedShared = batch.reuse.filter((e) => e.modes.every((m) => m === 'embedded-node'));
      a.ok(embeddedShared.length >= 1, '至少一个共享节点由两条路径以内嵌方式抵达');
    });

    test('内核：一条路径缺失散列引用只判该条无效，同批其余指令照常授权', () => {
      // 删除长键路径第 2 个节点（根分支槽 0 指向的扩展），池其余节点保留。
      const missingHash = toHex(keccak256(proofAuth[1]));
      const pool = fullPool.filter((b) => toHex(keccak256(b)) !== missingHash);
      const batch = batchFor([keyAuth, keyNo, snap.keys.otherAuthorized], pool);
      a.equal(batch.results[0].status, 'invalid');
      a.equal(batch.results[0].code, 'PATH_INCOMPLETE');
      a.equal(batch.results[0].firstFailedLayer, 2);
      a.equal(batch.results[1].status, 'invalid');
      a.equal(batch.results[1].firstFailedLayer, 2);
      a.equal(batch.results[2].status, 'authorized', '短键 a2 路径不经过缺失节点，必须照常授权');
    });

    test('内核：路径偏离（分支空槽）只影响该条，兄弟条目结论与层数不受影响', () => {
      const batch = batchFor([snap.keys.otherAuthorized, 'a3', 'a9', snap.keys.shortUnauthorized]);
      a.equal(batch.results[0].status, 'authorized');
      a.equal(batch.results[1].status, 'invalid');
      a.equal(batch.results[1].code, 'PATH_INCOMPLETE');
      a.equal(batch.results[2].code, 'PATH_INCOMPLETE');
      a.equal(batch.results[3].status, 'unauthorized');
      a.equal(batch.results[0].layers.length, 3);
      a.equal(batch.results[3].layers.length, 3);
    });

    test('内核：无法解析的标识按条隔离为 BAD_KEY，不阻断其余条目', () => {
      const batch = verifyBatch(
        snap.rootHash,
        [
          { keyHex: 'a2g', nibbles: null, parseError: '含有非十六进制字符' },
          entryFor(snap.keys.otherAuthorized),
        ],
        dedupePool(fullPool).nodes
      );
      a.equal(batch.results[0].status, 'invalid');
      a.equal(batch.results[0].code, 'BAD_KEY');
      a.equal(batch.results[0].firstFailedLayer, 0);
      a.equal(batch.results[1].status, 'authorized');
    });

    test('内核：池中不可达的非规范 RLP 节点列为冗余证据，不影响任何结论', () => {
      const junk = B('8100'); // 非规范单字节长形式，且其摘要不会被任何规范父节点引用
      const pool = dedupePool(fullPool.concat([junk])).nodes;
      const batch = verifyBatch(snap.rootHash, [entryFor(keyAuth), entryFor('a2')], pool);
      a.equal(batch.results[0].status, 'authorized');
      a.equal(batch.results[1].status, 'authorized');
      const junkEntry = batch.redundant.find((n) => n.nodeHash === toHex(keccak256(junk)));
      a.ok(junkEntry, '不可达的非规范节点必须出现在冗余证据中');
      a.equal(junkEntry.kind, 'unparseable');
    });

    test('内核：实际抵达的非规范散列子节点只令追随它的那条指令无效', () => {
      // 手工构造规范分支根：槽 3 引用一个非规范节点 X 的散列；槽 5 内嵌合法授权叶。
      const x = B('8100');
      const xHash = keccak256(x);
      const slots = new Array(17).fill(U());
      slots[3] = xHash;
      slots[5] = [B('20'), U(0x01)]; // 内嵌叶：HP 空剩余路径 + 值 01
      const rootBytes = rlp.encode(slots);
      const pool = [rootBytes, x];
      const batch = verifyBatch(
        keccak256(rootBytes),
        [entryFor('5'), entryFor('3')],
        pool
      );
      a.equal(batch.results[0].status, 'authorized');
      a.equal(batch.results[0].value, '01');
      a.equal(batch.results[1].status, 'invalid');
      a.equal(batch.results[1].code, 'RLP_NONCANONICAL');
      a.equal(batch.results[1].firstFailedLayer, 2);
    });

    test('内核：节点池不要求顺序，打乱后各条结论与复用表完全一致', () => {
      const shuffled = fullPool.map((b) => b).reverse();
      const a1 = batchFor([keyAuth, keyNo, 'a2']);
      const a2 = batchFor([keyAuth, keyNo, 'a2'], shuffled);
      a.deepEqual(a2.summary, a1.summary);
      a.deepEqual(a2.results.map((r) => [r.status, r.code, r.consumedPath]),
        a1.results.map((r) => [r.status, r.code, r.consumedPath]));
      a.deepEqual(a2.reuse.map((e) => e.nodeHash).sort(), a1.reuse.map((e) => e.nodeHash).sort());
    });

    test('内核：池模式不因叶后多余节点报 TAIL_DUPLICATE；多余节点成为冗余证据', () => {
      // 整池 + 目标键本身允许存在未消费节点（与单指令有序模式不同）。
      const batch = batchFor([snap.keys.otherAuthorized]);
      a.notEqual(batch.results[0].code, 'TAIL_DUPLICATE');
      a.ok(batch.redundant.length > 0, '未被短键路径消费的池节点应列为冗余');
    });

    test('内核：池节点只能由引用实际抵达——无人引用的合法叶节点是冗余证据', () => {
      const orphan = rlp.encode([hp.encode([9, 9], true), U(0x09)]); // 合法叶但无任何父节点指向
      const pool = dedupePool(fullPool.concat([orphan])).nodes;
      const batch = verifyBatch(snap.rootHash, [entryFor('a2')], pool);
      a.equal(batch.results[0].status, 'authorized');
      const orphanEntry = batch.redundant.find((n) => n.nodeHash === toHex(keccak256(orphan)));
      a.ok(orphanEntry);
      a.equal(orphanEntry.kind, 'leaf');
    });

    test('内核：根哈希不在池中 -> 各条 ROOT_MISMATCH（第 1 层）', () => {
      const wrong = Uint8Array.from(snap.rootHash);
      wrong[0] ^= 0xff;
      const batch = verifyBatch(wrong, [entryFor(keyAuth), entryFor('a2')], dedupePool(fullPool).nodes);
      for (const r of batch.results) {
        a.equal(r.status, 'invalid');
        a.equal(r.code, 'ROOT_MISMATCH');
        a.equal(r.firstFailedLayer, 1);
      }
    });

    test('内核：dedupePool 按摘要剔除重复节点并计数', () => {
      const dup = fullPool.concat([fullPool[0], fullPool[1], fullPool[0]]);
      const { nodes, duplicates } = dedupePool(dup);
      a.equal(duplicates, 3);
      a.equal(nodes.length, fullPool.length);
    });

    test('内核：verifyProofFromPool 与单指令 verifyProof 在同一有序证明上结论一致', () => {
      for (const [key, proof] of [[keyAuth, proofAuth], [keyNo, proofNo]]) {
        const single = verifyProof(snap.rootHash, bytesToNibbles(fromHex(key)), proof);
        const pooled = verifyProofFromPool(snap.rootHash, bytesToNibbles(fromHex(key)), proof);
        a.equal(pooled.status, single.status);
        a.equal(pooled.code, single.code);
        a.equal(pooled.consumedPath, single.consumedPath);
        a.equal(pooled.layers.length, single.layers.length);
      }
    });

    test('页面：批量页含汇总横幅/逐条结论/各自消费路径', () => {
      const batch = batchFor([keyAuth, keyNo, 'a3']);
      const page = buildBatchPage(batch, { rootHash: snap.rootHashHex, submittedPoolSize: fullPool.length, duplicates: 0 });
      a.match(page, /<title>离线指令授权快照批量复核结果<\/title>/);
      a.match(page, /已授权 1 条 · 未授权 1 条 · 无效 1 条/);
      a.match(page, new RegExp(keyAuth));
      a.match(page, new RegExp(keyNo));
      a.match(page, /仅清除本条旧结论/);
      a.match(page, /完整已消费半字节路径/);
      // 失败条显示首个失败层，成功条显示已授权
      a.match(page, /PATH_INCOMPLETE/);
      a.ok(page.includes('banner-title">指令 1 · 已授权'));
    });

    test('页面：共享节点表列出复用次数与对应指令，冗余证据单独成节', () => {
      const batch = batchFor([keyAuth, keyNo, 'a2']);
      const page = buildBatchPage(batch, { rootHash: snap.rootHashHex, submittedPoolSize: fullPool.length, duplicates: 0 });
      a.match(page, /共享节点复用/);
      a.match(page, /复用次数/);
      a.match(page, /2 次/);
      a.match(page, /冗余证据/);
      a.ok(batch.redundant.length > 0);
      for (const n of batch.redundant) a.match(page, new RegExp(n.nodeHash.slice(0, 16)));
      a.match(page, /内嵌|散列/);
    });

    test('页面：去重统计在元信息区呈现，HTML 内容做转义', () => {
      const dup = fullPool.concat([fullPool[0]]);
      const batch = verifyBatch(snap.rootHash, [entryFor(keyAuth), entryFor('a2')], dedupePool(dup).nodes);
      batch.deduplicated = 1;
      const page = buildBatchPage(batch, { rootHash: snap.rootHashHex, submittedPoolSize: dup.length, duplicates: 1 });
      a.match(page, /提交 \d+ 个，去重后 \d+ 个（剔除 1 个重复节点）/);
      a.ok(!page.includes('<script>'));
    });

    test('API：合法批量提交 200，结果与页面齐备', () => {
      const out = handleVerifyBatch({
        rootHash: snap.rootHashHex,
        keyHexes: [keyAuth, keyNo, 'a2'],
        proofNodes: fullPool.map((b) => toHex(b)).join('\n'),
      });
      a.equal(out.httpStatus, 200);
      a.deepEqual(out.result.summary, { authorized: 2, unauthorized: 1, invalid: 0 });
      a.equal(out.result.poolSize, fullPool.length);
      a.match(out.page, /批量结论/);
    });

    test('API：重复粘贴的共同前缀节点被去重并计数', () => {
      const nodes = fullPool.concat([fullPool[0], fullPool[2]]);
      const out = handleVerifyBatch({
        rootHash: snap.rootHashHex,
        keyHexes: ['a2', 'a1'],
        proofNodes: nodes.map((b) => toHex(b)),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.deduplicated, 2);
      a.equal(out.result.submittedPoolSize, nodes.length);
      a.equal(out.result.poolSize, fullPool.length);
      a.deepEqual(out.result.summary, { authorized: 1, unauthorized: 1, invalid: 0 });
    });

    test('API：标识数 1 条或超过 8 条均 400，2 至 8 条接受', () => {
      const nodes = fullPool.map((b) => toHex(b));
      const mk = (hexes) => handleVerifyBatch({ rootHash: snap.rootHashHex, keyHexes: hexes, proofNodes: nodes });
      a.equal(mk(['a2']).httpStatus, 400);
      a.match(mk(['a2']).error, /2 至 8/);
      const nine = Array.from({ length: 9 }, (_, i) => `0${i}`);
      a.equal(mk(nine).httpStatus, 400);
      a.match(mk(nine).error, /最多 8 条/);
      const two = mk(['a2', 'a1']);
      a.equal(two.httpStatus, 200);
    });

    test('API：keyHexes 支持换行/逗号文本与 JSON 数组两种形式', () => {
      a.deepEqual(parseKeyHexes('a2\na1\n01'), ['a2', 'a1', '01']);
      a.deepEqual(parseKeyHexes('a2, a1;01'), ['a2', 'a1', '01']);
      a.deepEqual(parseKeyHexes(['0xAB', 'cd']), ['0xAB', 'cd']);
      a.throws(() => parseKeyHexes('only'), /2 至 8/);
    });

    test('API：批量中单条坏标识不影响整批 HTTP 200 与其他条目', () => {
      const out = handleVerifyBatch({
        rootHash: snap.rootHashHex,
        keyHexes: 'a2\nzzz\na1',
        proofNodes: fullPool.map((b) => toHex(b)),
      });
      a.equal(out.httpStatus, 200);
      a.equal(out.result.results[0].status, 'authorized');
      a.equal(out.result.results[1].status, 'invalid');
      a.equal(out.result.results[1].code, 'BAD_KEY');
      a.equal(out.result.results[2].status, 'unauthorized');
    });

    test('API：根哈希长度错误等提交级问题返回 400', () => {
      const out = handleVerifyBatch({ rootHash: '0102', keyHexes: ['a2', 'a1'], proofNodes: '80' });
      a.equal(out.httpStatus, 400);
      a.match(out.error, /32 字节/);
    });

    test('入口页：含批量表单、去重节点池说明与 2–8 条限制', () => {
      const html = buildIndexPage();
      a.match(html, /id="batch-form"/);
      a.match(html, /name="keyHexes"/);
      a.match(html, /去重 RLP 节点池/);
      a.match(html, /2 至 8/);
      a.match(html, /\/api\/verify-batch/);
    });

    test('HTTP 冒烟：GET /api/sample-batch 返回根哈希/多条标识/节点池', async () => {
      const res = await http('/api/sample-batch');
      a.equal(res.status, 200);
      const data = await res.json();
      a.match(data.rootHash, /^[0-9a-f]{64}$/);
      a.ok(data.keyHexes.length >= 2 && data.keyHexes.length <= 8);
      a.ok(data.poolNodes.length >= data.keyHexes.length);
      // 示例池至少含一个任何示例路径都不消费的冗余节点
    });

    test('HTTP 冒烟：POST /api/verify-batch 返回三类结论并存的批量页', async () => {
      const sample = await (await http('/api/sample-batch')).json();
      const res = await postVerifyBatch(sample.rootHash, sample.keyHexes, sample.poolNodes.join('\n'));
      a.equal(res.status, 200);
      const data = await res.json();
      a.equal(data.result.kind, 'batch');
      a.ok(data.result.summary.authorized >= 1);
      a.ok(data.result.summary.invalid >= 1, '示例中 a3 应为无效条目');
      a.match(data.page, /批量结论/);
      a.match(data.page, /共享节点复用/);
      a.match(data.page, /冗余证据/);
    });
  });

  // ========== API 输入校验与 HTTP 杂项 ==========
  await suite('API 输入校验与 HTTP 杂项').run(async () => {
    test('API：根哈希长度错误返回 400', () => {
      const out = handleVerify({ rootHash: '0102', keyHex: keyAuth, proofNodes: toHex(proofAuth[0]) });
      a.equal(out.httpStatus, 400);
      a.match(out.error, /32 字节/);
    });

    test('API：非法十六进制返回 400', () => {
      const out = handleVerify({ rootHash: 'zz' + snap.rootHashHex.slice(2), keyHex: keyAuth, proofNodes: 'a0' });
      a.equal(out.httpStatus, 400);
    });

    test('API：空节点列表返回 400', () => {
      const out = handleVerify({ rootHash: snap.rootHashHex, keyHex: keyAuth, proofNodes: '  \n ' });
      a.equal(out.httpStatus, 400);
    });

    test('API：多行与逗号分隔解析一致', () => {
      const nodes = proofAuth.map((p) => toHex(p));
      const a1 = parseProofNodes(nodes.join('\n'));
      const a2 = parseProofNodes(nodes.join(','));
      const a3 = parseProofNodes(nodes.map((x) => '0x' + x));
      a.equal(a1.length, nodes.length);
      a.ok(a1.every((n, i) => equalBytes(n, a2[i]) && equalBytes(n, a3[i])));
    });

    test('页面：HTML 转义防止注入', () => {
      const res = verifyProof(U(1), [1], []); // BAD_ROOT 前的简单 invalid
      const page = buildResultPage(res, { rootHash: '<script>x</script>', keyHex: '"><b>', nodeCount: 0 });
      a.equal(page.includes('<script>x</script>'), false);
      a.ok(page.includes('&lt;script&gt;'));
    });

    test('入口页包含提交说明与启用承诺 01', () => {
      a.match(buildIndexPage(), /32 字节根哈希/);
      a.match(buildIndexPage(), /十六进制指令标识/);
      a.match(buildIndexPage(), /按根到叶排序的 RLP 节点/);
      a.match(buildIndexPage(), /01/);
    });

    test('HTTP 冒烟：/health 别名同样可用', async () => {
      const res = await http('/health');
      a.equal(res.status, 200);
      a.equal((await res.json()).status, 'ok');
    });

    test('HTTP 冒烟：未知路径 404 JSON', async () => {
      const res = await http('/nope');
      a.equal(res.status, 404);
      a.equal((await res.json()).error, '未找到该路径');
    });

    test('HTTP 冒烟：坏 JSON 请求体 400', async () => {
      const res = await http('/api/verify', { method: 'POST', body: '{not-json' });
      a.equal(res.status, 400);
      a.match((await res.json()).error, /JSON/);
    });
  });

  if (server) await new Promise((resolve) => server.close(resolve));

  const { passed, failed } = h.summary();
  console.log(`\n========================================`);
  console.log(`测试结果：${passed} 通过，${failed} 失败`);
  if (failed > 0) {
    process.exitCode = 1;
  } else {
    console.log('验收测试全部通过 ✅');
  }
}

main().catch((e) => {
  console.error('测试运行器异常：', e);
  process.exit(1);
});
