'use strict';
// 极简测试工具：零依赖，支持同步/异步用例与退出码统计。
// suite 内的 test() 即使漏写 await，其 Promise 也会被自动收集并在 suite 结束时统一等待。
const assert = require('node:assert/strict');

function createHarness() {
  let passed = 0;
  let failed = 0;
  const failures = [];
  const activeSuites = [];

  async function test(name, fn) {
    const label = [...activeSuites.map((s) => s.name), name].join(' › ');
    const run = Promise.resolve()
      .then(fn)
      .then(() => {
        passed += 1;
        console.log(`  ok - ${label}`);
      })
      .catch((e) => {
        failed += 1;
        failures.push({ label, e });
        console.log(`  FAIL - ${label}`);
        console.log(String(e && e.stack ? e.stack : e).split('\n').map((l) => '      ' + l).join('\n'));
      });
    if (activeSuites.length > 0) activeSuites[activeSuites.length - 1].pending.push(run);
    return run;
  }

  function suite(name) {
    return {
      run: async (fn) => {
        const ctx = { name, pending: [] };
        activeSuites.push(ctx);
        console.log(`\n● ${name}`);
        await fn();
        await Promise.all(ctx.pending);
        activeSuites.pop();
      },
    };
  }

  return {
    test,
    suite,
    assert,
    summary() {
      return { passed, failed, failures };
    },
  };
}

module.exports = { createHarness, assert };
