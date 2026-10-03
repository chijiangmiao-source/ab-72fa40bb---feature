'use strict';
// 结果页构建：把核验内核的结构化结果渲染为静态 HTML（Node 与浏览器共用）。
// Node 端由 HTTP 服务在服务端渲染后返回；页面构建逻辑可在无 DOM 的测试中直接断言。

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const KIND_LABEL = {
  leaf: '叶节点',
  extension: '扩展节点',
  branch: '分支节点',
  'branch-value': '分支节点（值槽）',
};

const REF_LABEL = {
  'root-commitment': '根承诺（32 字节根哈希）',
  'hash-32': '32 字节散列引用',
  'embedded-node': '内嵌节点（父节点 RLP 内联）',
};

function statusBanner(result) {
  if (result.status === 'authorized') {
    return `<div class="banner banner-ok" role="status">
      <span class="banner-title">已授权</span>
      <span class="banner-sub">证明有效，叶值为 <code>0x${esc(result.value)}</code>（启用承诺 <code>01</code>）</span>
    </div>`;
  }
  if (result.status === 'unauthorized') {
    return `<div class="banner banner-no" role="status">
      <span class="banner-title">未授权</span>
      <span class="banner-sub">路径完整抵达叶节点，但叶值为 <code>0x${esc(result.value)}</code>，并非启用承诺 <code>01</code>。路径证据保留如下。</span>
    </div>`;
  }
  return `<div class="banner banner-bad" role="alert">
    <span class="banner-title">证明无效</span>
    <span class="banner-sub">首个失败层：<strong>第 ${esc(result.firstFailedLayer)} 层</strong>（${esc(result.code)}）——${esc(result.reason)}</span>
  </div>`;
}

function renderLayer(layer, failedLayer) {
  const isFailed = failedLayer === layer.layer;
  const rows = [];
  rows.push(['层号', `第 ${layer.layer} 层`]);
  rows.push(['节点类型', KIND_LABEL[layer.kind] || layer.kind]);
  rows.push(['引用方式', REF_LABEL[layer.reference] || layer.reference]);
  if (layer.embeddedInLayer) rows.push(['内嵌于', `第 ${layer.embeddedInLayer} 层节点的 RLP 负载`]);
  rows.push(['节点摘要（Keccak-256）', `<code class="hash">0x${esc(layer.nodeHash)}</code>`]);
  rows.push(['RLP 长度', `${layer.rlpSize} 字节${layer.rlpSize < 32 ? '（< 32，可内嵌）' : '（≥ 32，须散列引用）'}`]);
  if (layer.hpPrefix !== undefined) rows.push(['十六进制前缀', `<code>0x${esc(layer.hpPrefix)}</code>`]);
  if (layer.slot !== undefined) {
    rows.push(['分支槽', layer.slot === 16 ? '16（值槽）' : `0x${layer.slot.toString(16)}`]);
  }
  if (layer.consumedNibbles !== undefined && layer.consumedNibbles !== '') {
    rows.push(['本层消费半字节', `<code>${esc(layer.consumedNibbles)}</code>`]);
  }
  if (layer.cumulativePath !== undefined) {
    rows.push(['累计已消费路径', `<code>${esc(layer.cumulativePath) || '（空）'}</code>`]);
  }
  if (layer.childReference) {
    const refDesc = REF_LABEL[layer.childReference] || layer.childReference;
    rows.push(['子节点引用方式', layer.childHash ? `${refDesc} <code class="hash">0x${esc(layer.childHash)}</code>` : refDesc]);
  }
  if (layer.value !== undefined) rows.push(['叶/槽值', `<code>0x${esc(layer.value)}</code>`]);

  const tds = rows
    .map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td>${v}</td></tr>`)
    .join('\n');
  return `<section class="layer${isFailed ? ' layer-failed' : ''}" aria-label="第 ${layer.layer} 层">
  <h3>第 ${layer.layer} 层 · ${esc(KIND_LABEL[layer.kind] || layer.kind)}${isFailed ? ' · 首个失败层' : ''}</h3>
  <table><tbody>${tds}</tbody></table>
</section>`;
}

function renderFailureMarker(result) {
  if (result.status !== 'invalid') return '';
  return `<section class="layer layer-failed" aria-label="首个失败层">
  <h3>第 ${esc(result.firstFailedLayer)} 层 · 核验中止</h3>
  <p class="reason"><strong>${esc(result.code)}</strong>：${esc(result.reason)}</p>
  <p class="note">旧成功结论已清除；以上各层为中止前已核验保留的路径证据。</p>
</section>`;
}

function buildResultPage(result, input) {
  const meta = input || {};
  const layersHtml = result.layers.map((l) => renderLayer(l, result.firstFailedLayer)).join('\n');
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照复核结果</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照复核</h1>
  ${statusBanner(result)}
  <section class="meta" aria-label="核验输入">
    <h2>核验输入</h2>
    <dl>
      <dt>32 字节根哈希</dt><dd><code class="hash">0x${esc(meta.rootHash || '')}</code></dd>
      <dt>十六进制指令标识</dt><dd><code>0x${esc(meta.keyHex || '')}</code></dd>
      <dt>证明 RLP 节点数</dt><dd>${esc(meta.nodeCount ?? result.layers.length)}（根到叶顺序）</dd>
      <dt>完整已消费半字节路径</dt><dd><code>${esc(result.consumedPath || '（无）')}</code></dd>
    </dl>
  </section>
  <h2>逐层节点回放</h2>
  ${layersHtml || '<p class="note">无已核验层。</p>'}
  ${renderFailureMarker(result)}
  <p class="back"><a href="/">返回导入页</a></p>
</main>
</body>
</html>`;
}

const STYLES = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; font-family: system-ui, "PingFang SC", "Microsoft YaHei", sans-serif; line-height:1.6; }
.page { max-width: 920px; margin: 0 auto; padding: 24px 18px 64px; }
h1 { font-size: 1.5rem; } h2 { margin-top: 28px; font-size: 1.15rem; }
.banner { border-radius: 10px; padding: 16px 18px; margin: 18px 0; display:flex; flex-direction:column; gap:4px; border:2px solid; }
.banner-title { font-size: 1.25rem; font-weight: 700; }
.banner-ok { border-color:#1a7f37; background:rgba(34,139,64,.12); }
.banner-no { border-color:#9a6700; background:rgba(190,145,0,.12); }
.banner-bad { border-color:#cf222e; background:rgba(207,34,46,.10); }
.layer { border:1px solid rgba(128,128,128,.4); border-radius:10px; padding:12px 16px; margin:14px 0; }
.layer-failed { border-color:#cf222e; border-width:2px; background:rgba(207,34,46,.06); }
.layer h3 { margin: 4px 0 8px; font-size: 1rem; }
table { border-collapse: collapse; width:100%; }
th,td { text-align:left; vertical-align:top; padding:5px 10px 5px 0; border-bottom:1px dashed rgba(128,128,128,.35); font-weight:400; }
th { width: 13em; color: rgba(128,128,128,1); white-space:nowrap; }
code { word-break: break-all; }
.hash { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:.85rem; }
.meta dl { display:grid; grid-template-columns: 12em 1fr; gap:4px 16px; }
.meta dt { font-weight:600; } .meta dd { margin:0; word-break:break-all; }
.reason { color:#cf222e; font-weight:600; }
.note { color: rgba(128,128,128,1); font-size:.92rem; }
form textarea, form input { width:100%; font-family: ui-monospace, Menlo, Consolas, monospace; font-size:.85rem; }
form textarea { min-height: 120px; }
label { font-weight:600; display:block; margin:12px 0 4px; }
button { margin-top:16px; padding:8px 18px; font-size:1rem; border-radius:8px; cursor:pointer; }
button.secondary { margin-left:10px; padding:8px 12px; font-size:.88rem; opacity:.9; }
.error-line { color:#cf222e; font-weight:600; white-space:pre-wrap; }
`;

function buildIndexPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照复核</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照复核</h1>
  <p>地面审查员导入离线授权快照：提交 <strong>32 字节根哈希</strong>、<strong>十六进制指令标识</strong> 与<strong>按根到叶排序的 RLP 节点</strong>。系统核验该指令是否被承诺为启用（叶值 <code>01</code>）。</p>
  <form id="verify-form" method="post" action="/api/verify">
    <label for="rootHash">32 字节根哈希（hex，可带 0x）</label>
    <input id="rootHash" name="rootHash" required placeholder="0x..." autocomplete="off">
    <label for="keyHex">十六进制指令标识（hex，可带 0x）</label>
    <input id="keyHex" name="keyHex" required placeholder="a1b2c3..." autocomplete="off">
    <label for="proofNodes">RLP 节点（每行一个 hex；或填写由节点 hex 组成的 JSON 数组）</label>
    <textarea id="proofNodes" name="proofNodes" required placeholder="0xf8...&#10;0xe3..."></textarea>
    <p id="form-error" class="error-line" role="alert"></p>
    <button type="submit">核验授权</button>
    <button type="button" id="load-ok" class="secondary">载入示例：已授权（叶值 01）</button>
    <button type="button" id="load-no" class="secondary">载入示例：未授权（叶值 00）</button>
  </form>
</main>
<script>
${CLIENT_SCRIPT}
</script>
</body>
</html>`;
}

const CLIENT_SCRIPT = `
const form = document.getElementById('verify-form');
const fill = (c) => {
  document.getElementById('rootHash').value = c.rootHash;
  document.getElementById('keyHex').value = c.keyHex;
  document.getElementById('proofNodes').value = c.proofNodes.join('\\n');
};
for (const [id, kind] of [['load-ok','authorized'], ['load-no','unauthorized']]) {
  document.getElementById(id).addEventListener('click', async () => {
    const errEl = document.getElementById('form-error');
    errEl.textContent = '';
    try {
      const res = await fetch('/api/sample');
      const data = await res.json();
      fill(data.cases[kind]);
    } catch (e) {
      errEl.textContent = '示例载入失败：' + e.message;
    }
  });
}
form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errEl = document.getElementById('form-error');
  errEl.textContent = '';
  const payload = {
    rootHash: document.getElementById('rootHash').value.trim(),
    keyHex: document.getElementById('keyHex').value.trim(),
    proofNodes: document.getElementById('proofNodes').value
  };
  try {
    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = (data && data.error) ? data.error : ('请求失败：HTTP ' + res.status);
      return;
    }
    document.open();
    document.write(data.page);
    document.close();
  } catch (e) {
    errEl.textContent = '请求失败：' + e.message;
  }
});
`;

module.exports = { buildResultPage, buildIndexPage, esc };
