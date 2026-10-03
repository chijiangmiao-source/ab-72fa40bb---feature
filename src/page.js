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
  if (layer.poolIndex !== undefined && layer.poolIndex !== null) {
    rows.push(['节点池序号', `#${layer.poolIndex}（去重节点池）`]);
  }
  if (layer.shared) {
    const who = layer.shared.commands.map((k) => `<code>0x${esc(k)}</code>`).join('、');
    rows.push(['共享复用', `<span class="shared-badge">被 ${layer.shared.reuseCount} 条路径复用</span>：${who}`]);
  }
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

const BATCH_STATUS_LABEL = {
  authorized: ['已授权', 'banner-ok'],
  unauthorized: ['未授权', 'banner-no'],
  invalid: ['无效', 'banner-bad'],
};

function batchSummary(batch) {
  const counts = { authorized: 0, unauthorized: 0, invalid: 0 };
  for (const r of batch.results) counts[r.result.status] += 1;
  return counts;
}

function renderBatchCommand(item, failedLayer) {
  const { keyHex, result } = item;
  const [label, cls] = BATCH_STATUS_LABEL[result.status] || [result.status, 'banner-bad'];
  const layersHtml = result.layers.map((l) => renderLayer(l, result.firstFailedLayer)).join('\n');
  const sharedHtml = (result.sharedNodes || []).length === 0 ? '' : `
  <div class="shared-note">
    <h4>本路径共享节点复用</h4>
    <ul>
      ${result.sharedNodes.map((s) => `<li>池节点 <code>#${s.poolIndex}</code> <code class="hash">0x${esc(s.nodeHash.slice(0, 16))}…</code>：被 <strong>${s.reuseCount}</strong> 条路径消费，同批指令 ${s.commands.map((k) => `<code>0x${esc(k)}</code>`).join('、')}</li>`).join('\n')}
    </ul>
  </div>`;
  let head;
  if (result.status === 'invalid') {
    head = `<div class="banner ${cls} banner-compact" role="alert">
      <span class="banner-title"><code>0x${esc(keyHex)}</code> · 无效</span>
      <span class="banner-sub">首个失败层：<strong>第 ${esc(result.firstFailedLayer)} 层</strong>（${esc(result.code)}）——${esc(result.reason)}</span>
      <span class="banner-sub">本条旧成功结论已清除；同批其他指令的核验不受影响。</span>
    </div>`;
  } else {
    head = `<div class="banner ${cls} banner-compact" role="status">
      <span class="banner-title"><code>0x${esc(keyHex)}</code> · ${label}</span>
      <span class="banner-sub">${result.status === 'authorized'
        ? `证明有效，叶值为 <code>0x${esc(result.value)}</code>（启用承诺 <code>01</code>）`
        : `路径完整抵达叶节点，叶值为 <code>0x${esc(result.value)}</code>，并非启用承诺 <code>01</code>`}；已消费路径 <code>${esc(result.consumedPath || '（空）')}</code></span>
    </div>`;
  }
  const failureMarker = result.status === 'invalid' ? renderFailureMarker(result) : '';
  return `<section class="command" aria-label="指令 0x${esc(keyHex)} 的复核结论">
  ${head}
  ${layersHtml ? `<details${result.status === 'invalid' ? ' open' : ''}><summary>逐层节点回放（${result.layers.length} 层，已消费 <code>${esc(result.consumedPath || '（空）')}</code>）</summary>${layersHtml}</details>` : '<p class="note">无已核验层。</p>'}
  ${sharedHtml}
  ${failureMarker}
</section>`;
}

function renderSharedTable(batch) {
  if (batch.shared.length === 0) {
    return '<p class="note">本批各路径没有使用任何共同节点。</p>';
  }
  const rows = batch.shared.map((s) => `<tr>
    <td><code>#${s.poolIndex}</code></td>
    <td><code class="hash">0x${esc(s.nodeHash)}</code></td>
    <td>${s.rlpSize}</td>
    <td><strong>${s.reuseCount}</strong></td>
    <td>${s.commands.map((k) => `<code>0x${esc(k)}</code>`).join('、')}</td>
  </tr>`).join('\n');
  return `<table class="grid">
    <thead><tr><th>池序号</th><th>节点摘要（Keccak-256）</th><th>RLP 字节</th><th>复用次数</th><th>对应指令</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderRedundantList(batch) {
  if (batch.redundant.length === 0) {
    return '<p class="note">节点池中的全部节点均至少被一条目标路径消费，无冗余证据。</p>';
  }
  const items = batch.redundant.map((n) => `<li>池节点 <code>#${n.poolIndex}</code> <code class="hash">0x${esc(n.nodeHash)}</code>（${n.rlpSize} 字节${n.decodeErrorCode ? `，${esc(n.decodeErrorCode)} 无法解码` : ''}）——未被任何目标路径消费</li>`).join('\n');
  return `<ul class="redundant">${items}</ul>`;
}

function buildBatchPage(batch, input) {
  const meta = input || {};
  const counts = batchSummary(batch);
  const title = counts.invalid > 0
    ? `批量复核完成：${counts.authorized} 已授权 / ${counts.unauthorized} 未授权 / ${counts.invalid} 无效`
    : `批量复核完成：${counts.authorized} 已授权 / ${counts.unauthorized} 未授权`;
  const commandsHtml = batch.results.map((item) => renderBatchCommand(item)).join('\n');
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>离线指令授权快照批量复核结果</title>
<style>${STYLES}</style>
</head>
<body>
<main class="page">
  <h1>离线指令授权快照批量复核</h1>
  <div class="banner banner-neutral" role="status">
    <span class="banner-title">${esc(title)}</span>
    <span class="banner-sub">各条指令均从同一 32 字节根哈希独立追随引用；单条失败不影响同批其余指令。</span>
  </div>
  <section class="meta" aria-label="批量核验输入">
    <h2>批量核验输入</h2>
    <dl>
      <dt>32 字节根哈希</dt><dd><code class="hash">0x${esc(meta.rootHash || '')}</code></dd>
      <dt>指令标识（${(meta.keyHexes || batch.results.map((r) => r.keyHex)).length} 条）</dt><dd>${(meta.keyHexes || batch.results.map((r) => r.keyHex)).map((k) => `<code>0x${esc(k)}</code>`).join('、')}</dd>
      <dt>提交节点数 / 去重后池大小</dt><dd>${esc(batch.submittedNodeCount)} 个提交，去重后 <strong>${esc(batch.poolNodeCount)}</strong> 个池节点${batch.duplicateNodeCount > 0 ? `（去除 ${esc(batch.duplicateNodeCount)} 个重复粘贴）` : ''}</dd>
    </dl>
  </section>

  <h2>逐条结论与已消费路径</h2>
  ${commandsHtml}

  <h2>共享节点复用统计</h2>
  ${renderSharedTable(batch)}

  <h2>冗余证据（未被任何目标路径消费的池节点）</h2>
  ${renderRedundantList(batch)}

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
.banner-neutral { border-color: rgba(128,128,128,.7); background: rgba(128,128,128,.10); }
.banner-compact { padding: 10px 14px; }
.banner-compact .banner-title { font-size: 1.02rem; }
.command { border:2px solid rgba(128,128,128,.35); border-radius:12px; padding:12px 16px; margin:18px 0; }
.command details { margin-top: 8px; }
.command summary { cursor:pointer; font-weight:600; margin:6px 0; }
.command details .layer { margin: 10px 0; }
.shared-badge { display:inline-block; padding:1px 8px; border-radius:999px; background:rgba(68,120,220,.15); border:1px solid rgba(68,120,220,.5); font-weight:600; font-size:.85rem; }
.shared-note { margin:10px 0; padding:8px 14px; border-left:3px solid rgba(68,120,220,.6); background:rgba(68,120,220,.06); border-radius:0 8px 8px 0; }
.shared-note h4 { margin:4px 0; font-size:.95rem; }
table.grid { border-collapse:collapse; width:100%; font-size:.9rem; }
table.grid th, table.grid td { border-bottom:1px solid rgba(128,128,128,.35); padding:6px 8px; vertical-align:top; white-space:normal; width:auto; color:inherit; }
table.grid thead th { font-weight:700; }
ul.redundant { margin:6px 0; padding-left: 1.4em; }
.mode-tabs { display:flex; gap:10px; margin:14px 0 4px; }
.mode-tabs button { margin:0; }
.mode-tabs button.active { outline:2px solid #4478dc; }
#batch-fields { display:none; border-top:1px dashed rgba(128,128,128,.5); margin-top:14px; padding-top:6px; }
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
  <p>地面审查员导入离线授权快照：提交 <strong>32 字节根哈希</strong>、<strong>十六进制指令标识</strong> 与<strong>按根到叶排序的 RLP 节点</strong>。系统按以太坊式 MPT 存在性证明规则核验指令是否被承诺为启用（叶值 <code>01</code>）。</p>
  <div class="mode-tabs" role="tablist" aria-label="复核模式">
    <button type="button" id="mode-single" class="active" role="tab" aria-selected="true">单指令复核</button>
    <button type="button" id="mode-batch" role="tab" aria-selected="false">批量复核（2–8 条共享节点池）</button>
  </div>
  <form id="verify-form" method="post" action="/api/verify">
    <label for="rootHash">32 字节根哈希（hex，可带 0x）</label>
    <input id="rootHash" name="rootHash" required placeholder="0x..." autocomplete="off">
    <div id="single-fields">
      <label for="keyHex">十六进制指令标识（hex，可带 0x）</label>
      <input id="keyHex" name="keyHex" placeholder="a1b2c3..." autocomplete="off">
    </div>
    <div id="batch-fields">
      <label for="keyHexes">十六进制指令标识（2–8 条，每行一个；或 JSON 数组；可带 0x，自动去重）</label>
      <textarea id="keyHexes" name="keyHexes" placeholder="0123...&#10;fedc...&#10;a2" style="min-height:84px"></textarea>
    </div>
    <label for="proofNodes">RLP 节点（每行一个 hex；或填写由节点 hex 组成的 JSON 数组）</label>
    <textarea id="proofNodes" name="proofNodes" required placeholder="0xf8...&#10;0xe3..."></textarea>
    <p id="form-hint" class="note">单指令模式：节点须按根到叶排序。</p>
    <p id="form-error" class="error-line" role="alert"></p>
    <button type="submit" id="submit-btn">核验授权</button>
    <button type="button" id="load-ok" class="secondary">载入示例：已授权（叶值 01）</button>
    <button type="button" id="load-no" class="secondary">载入示例：未授权（叶值 00）</button>
    <button type="button" id="load-batch" class="secondary">载入示例：批量复核</button>
  </form>
</main>
<script>
${CLIENT_SCRIPT}
</script>
</body>
</html>`;
}

const CLIENT_SCRIPT = `
let batchMode = false;
const form = document.getElementById('verify-form');
const singleFields = document.getElementById('single-fields');
const batchFields = document.getElementById('batch-fields');
const btnSingle = document.getElementById('mode-single');
const btnBatch = document.getElementById('mode-batch');
const submitBtn = document.getElementById('submit-btn');
const hint = document.getElementById('form-hint');
const setMode = (batch) => {
  batchMode = batch;
  btnSingle.classList.toggle('active', !batch);
  btnBatch.classList.toggle('active', batch);
  btnSingle.setAttribute('aria-selected', String(!batch));
  btnBatch.setAttribute('aria-selected', String(batch));
  singleFields.style.display = batch ? 'none' : '';
  batchFields.style.display = batch ? '' : 'none';
  form.action = batch ? '/api/verify-batch' : '/api/verify';
  submitBtn.textContent = batch ? '批量核验授权' : '核验授权';
  hint.textContent = batch
    ? '批量模式：所有指令共享同一根哈希与一个去重后的 RLP 节点池，无需为每条指令重复粘贴共同前缀；节点顺序不限。'
    : '单指令模式：节点须按根到叶排序。';
};
btnSingle.addEventListener('click', () => setMode(false));
btnBatch.addEventListener('click', () => setMode(true));

const fillSingle = (c) => {
  setMode(false);
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
      fillSingle(data.cases[kind]);
    } catch (e) {
      errEl.textContent = '示例载入失败：' + e.message;
    }
  });
}
document.getElementById('load-batch').addEventListener('click', async () => {
  const errEl = document.getElementById('form-error');
  errEl.textContent = '';
  try {
    const res = await fetch('/api/sample-batch');
    const data = await res.json();
    setMode(true);
    document.getElementById('rootHash').value = data.rootHash;
    document.getElementById('keyHexes').value = data.keyHexes.join('\\n');
    document.getElementById('proofNodes').value = data.proofNodes.join('\\n');
  } catch (e) {
    errEl.textContent = '批量示例载入失败：' + e.message;
  }
});
form.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const errEl = document.getElementById('form-error');
  errEl.textContent = '';
  const payload = {
    rootHash: document.getElementById('rootHash').value.trim(),
    proofNodes: document.getElementById('proofNodes').value
  };
  if (batchMode) {
    payload.keyHexes = document.getElementById('keyHexes').value;
  } else {
    payload.keyHex = document.getElementById('keyHex').value.trim();
  }
  try {
    const res = await fetch(form.action, {
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

module.exports = { buildResultPage, buildBatchPage, buildIndexPage, esc };
