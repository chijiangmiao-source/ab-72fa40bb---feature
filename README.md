# 离线指令授权快照复核

地面审查员导入**离线指令授权快照**并核验某条十六进制指令是否被承诺为“启用”（叶值 `01`）。
系统按以太坊式 **Merkle Patricia Trie（MPT）存在性证明** 规则离线核验，无需联网、零运行时依赖。

## 提交内容

审查员在静态入口页提交三项：

| 字段 | 要求 |
|---|---|
| 根哈希 | 恰好 **32 字节**（hex，可带 `0x`） |
| 十六进制指令标识 | 偶数长度 hex 串，按半字节（nibble）在树中定位 |
| RLP 节点 | **按根到叶排序**的节点 hex，每行一个（也接受 JSON 数组） |

系统从 32 字节根哈希出发，沿证明逐层校验散列承诺、HP 紧凑路径与半字节消费，最终读取叶值。

## 判定与结果页

- **证明有效且叶值为 `01`** → 顶部绿色横幅 **“已授权”**，并逐层列出：
  - 节点摘要（Keccak-256）、节点类型与 RLP 长度；
  - 本层/累计**已消费的半字节路径**；
  - 子节点以**内嵌节点**（父 RLP 内联，仅 <32 字节）还是 **32 字节散列**引用；
  - 内嵌层标注“内嵌于”哪一层。供审查员逐层回放。
- **路径完整抵达叶但叶值非 `01`** → 明确显示 **“未授权”**，完整保留路径证据。
- 下列异常判为 **证明无效**，标明**首个失败层**并清除旧成功结论：

  | 类别 | code | 含义 |
  |---|---|---|
  | 父子引用不符 | `REF_MISMATCH` / `ROOT_MISMATCH` | 子节点 Keccak 与父引用（或根哈希）不一致 |
  | 重复尾节点 | `TAIL_DUPLICATE` | 抵达叶/值槽后仍有多余证明节点 |
  | 路径残缺 | `PATH_INCOMPLETE` / `PATH_MISMATCH` | 散列引用缺节点、分支空槽、路径对不上 |
  | 十六进制前缀错误 | `HP_INVALID` | HP/Compact 前缀标志位非法 |
  | RLP 非规范 | `RLP_NONCANONICAL` | 单字节长形式、长形短用、前导零等 |
  | RLP 截断/结构错误 | `RLP_INVALID` | 长度声明超出输入、深度超限等 |

## 运行（Compose）

需要安装 Docker / Docker Compose。宿主端口可用 `WEB_PORT` 配置（默认 `8080`）：

```bash
# 仅启动页面/API
docker compose up web
# 自定义宿主端口
WEB_PORT=9090 docker compose up web
# 浏览器打开 http://localhost:8080 （或配置的端口）
```

健康检查：`GET /healthz` 返回 `200 {"status":"ok",...}`。入口页提供
“载入示例：已授权 / 未授权”按钮，可直接观察三类复核结论。

### 验收服务 `verify`

Compose 提供名为 **`verify`** 的一次性服务：等待 `web` 健康后，在
**有效授权、篡改子节点引用、非规范 RLP** 三类场景间穿插运行——

1. `test/run-all.js`：进程内的**证明校验内核测试**与**页面构建检查**（三场景交替编排）；
2. `test/http-smoke.js`：对 Compose 启动的 `web` 做**页面与健康端点的 API/HTTP 冒烟**。

执行完毕即退出，并以退出码报告验收结果（`0` 全绿，非 `0` 存在失败）：

```bash
docker compose up --build verify        # 前台运行，观察输出
docker compose rm -f verify 2>/dev/null; docker compose run --build verify; echo "exit=$?"
```

## 本地开发（无需 Docker）

要求 Node.js ≥ 20，全程零依赖：

```bash
npm test                 # 进程内内核 + 页面 + 临时 HTTP 冒烟（45 项）
PORT=8123 npm start      # 启动服务
BASE_URL=http://127.0.0.1:8123 node test/http-smoke.js
```

## 目录结构

```
src/
  keccak.js          Keccak-256（以太坊填充 0x01 变体）纯 JS 实现
  rlp.js             规范/宽容双模式 RLP 编解码，拒绝截断与非规范
  hexpath.js         MPT 紧凑十六进制前缀（HP/Compact）
  hexutil.js         hex/字节/半字节工具
  trie.js            标准 MPT 构建器与证明生成（夹具/示例快照用）
  verifier.js        证明核验内核：逐层回放 + 首个失败层定位
  page.js            结果页/入口页 HTML 构建（可在无 DOM 下单测）
  verify-api.js      /api/verify 输入解析与结果组装
  sample-snapshot.js 内置离线示例快照
  server.js          零依赖 HTTP 服务（/、/healthz、/api/verify、/api/sample）
test/
  harness.js         零依赖测试框架
  fixtures.js        复用生产侧快照构造器
  run-all.js         三场景穿插的内核/页面/HTTP 测试总入口
  http-smoke.js      对运行中服务的端到端 HTTP 冒烟
```

## 正确性依据

- Keccak-256 输出对照标准向量（空串、`abc`）。
- MPT 根哈希与全部 ≥32 字节节点的 RLP 编码，均与参考实现
  [`merkle-patricia-tree@4`](https://www.npmjs.com/package/merkle-patricia-tree)
  逐字节一致。
