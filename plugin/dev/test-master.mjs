/**
 * 主密钥派生路径的端到端测试：
 *   fixture 用 enc_key = PBKDF2(master, salt, 256000) 加密
 *   → ensureKeys(masterKey) 应自动派生并通过 HMAC
 *   → 错误主密钥必须被拒绝
 */
import { execFileSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import assert from 'node:assert/strict'

import * as store from '../lib/store.js'

const root = mkdtempSync(join(tmpdir(), 'wxmaster-'))
const accDir = 'wxid_mastertest_ab12'
const accountRoot = join(root, 'xwechat_files', accDir)
const dbDir = join(accountRoot, 'db_storage')
const master = randomBytes(32).toString('hex')

const info = JSON.parse(execFileSync(process.execPath, [
  join(import.meta.dirname, 'make-fixture.mjs'), dbDir, '--master', master,
], { encoding: 'utf8' }))
console.log(`[1] fixture 就绪: salt=${info.salt.slice(0, 8)}… enc_key=${info.key.slice(0, 8)}…`)

const cfg = { dbDir: join(root, 'xwechat_files'), cacheDir: join(root, 'cache'), masterKey: master }
const account = store.resolveAccount(cfg)
assert.equal(account.account, 'wxid_mastertest')

const keys = store.ensureKeys(account, cfg)
assert.equal(keys.source, 'master-key')
assert.ok(keys.keys['session/session.db'], '应从主密钥派生 session.db 的 key')
assert.equal(keys.keys['session/session.db'].enc_key, info.key, '派生结果应与 fixture 的 enc_key 一致')
console.log(`[2] 主密钥派生成功: ${Object.keys(keys.keys).length} 个库, 与 fixture 一致 ✓`)

// 缓存必须能复用（第二次不重新派生）
const again = store.ensureKeys(account, cfg)
assert.equal(again.generatedAt, keys.generatedAt)
console.log('[3] 二次调用走缓存 ✓')

// 错误主密钥必须被拒
const bad = randomBytes(32).toString('hex')
assert.throws(
  () => store.deriveKeysFromMaster(account, bad, cfg),
  /主密钥和这个账号的数据库对不上/,
)
console.log('[4] 错误主密钥被拒 ✓')

// 格式错误要给人话
assert.throws(() => store.deriveKeysFromMaster(account, 'zzzz', cfg), /64 位十六进制/)
console.log('[5] 非法格式被拒 ✓')

// 原文/带 x'' 包裹都能接受
const wrapped = store.deriveKeysFromMaster(account, `x'${master}'`, cfg)
assert.ok(wrapped.keys['session/session.db'])
console.log('[6] 兼容 x\'...\' 包裹写法 ✓')

console.log('\n全部通过  ' + root)
