# FOTA 服务：间歇联网终端的分批次固件升级

一套可直接运行的参考实现：运营人员上传固件版本后，按**硬件批次 + 阶段（金丝雀→放量）**
逐级灰度；间歇联网终端只领取与自身**型号 / 引导程序版本 / 当前版本**兼容的镜像；
**分块校验续传**；安装失败 A/B 回滚到上一可启动版本并上报原因；批次可暂停/熔断，
且**失败率越阈自动停止扩散**；所有领取与回执幂等，重复上线、重复回执不重复占名额。

发布链路默认**离线签名**：每个发布都有确定性序列化的签名元数据（制品摘要、型号、
显示版本、单调递增安全计数器、过期时间），终端在进入关键刷写区之前完成
**信任链 / 签名 / 过期 / 摘要 / 计数器**五项校验；根密钥轮换需要新旧根双重授权，
长期离线的设备一次唤醒即可连续 traverse 多代轮换；所有拒绝都会留下
**持久、可查询、重试幂等**的失败回执，且绝不触碰当前可启动槽。

在此之上是一层**软件供应公证**：控制面每次登记信任交接（根轮换）或制品（签名发布）
都把规范编码的条目**追加到 Merkle 树尾**并签发**公证钥匙签署的检查点**（同一事务，
崩溃无中间态）；终端领取时收到**成员见证 + 自上次检查点以来的连续见证**（均为对数
规模），先验证再触碰备用分区，并把新检查点与领取结果作为**一次原子状态变更**落盘；
一旦发现**同树高不同根 / 树高缩小 / 历史无法衔接 / 见证被改**，终端上报疑点材料
（内容去重、可查询），该机型被**永久置入观察禁区**——已动盘的设备允许收尾，
未动盘的设备立即停下，服务重启后禁区依然生效。

## 快速开始（可复现入口）

```bash
# 方式一：容器（推荐，零本地依赖）
docker compose up --build -d
./scripts/demo.sh                 # 容器内驱动 10 台模拟终端走完灰度/断网/熔断
docker compose logs -f fota

# 方式二：容器内跑测试（镜像即测试载体，结果可复现）
docker build -t fota-service:dev .
docker run --rm fota-service:dev test -v

# 方式三：本地 Python
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8080
python -m pytest -q               # 51 项测试
```

- `Dockerfile` 的 `ENTRYPOINT` 是 `entrypoint.sh`：无参数起 API；`test` 跑 pytest；
  其它参数原样执行（demo 用它在同一镜像里跑模拟器）。
- 所有路径、阈值、块大小均由环境变量决定（见下），compose 与测试用同一镜像、同一套默认值。

## 一分钟走查 API

```bash
# 1. 运营上传镜像（multipart：固件 + 型号/版本/引导程序兼容窗口）
curl -F file=@firmware.bin -F model=term-x1 -F version=2.0.0 \
     -F min_bootloader=1.0.0 -F max_bootloader=1.99.0 \
     http://localhost:8080/api/admin/images

# 1b. 离线签名（私钥不接触服务）：先建信任根 v1（自签名），再发布签名发布。
#     元数据为规范化 JSON（键排序、紧凑分隔符），签名走 ed25519；
#     测试里的 tests/conftest.py::TrustKit 与 app/trust.py 演示了完整签名流程。
curl -X POST localhost:8080/api/admin/roots \
     -d '{"metadata":<root元数据>,"signatures":[...],"idempotency_key":"..."}' ...
curl -X POST localhost:8080/api/admin/releases \
     -d '{"image_id":"<img>","metadata":<release元数据>,"signatures":[...],"idempotency_key":"..."}' ...

# 2. 基于镜像建发布活动，再建按硬件批次的灰度阶段（quota 支持绝对名额/百分比）
curl -X POST localhost:8080/api/admin/campaigns -d '{"name":"q3","image_id":"<img>"}' ...
curl -X POST localhost:8080/api/admin/batches -d '{"campaign_id":"<c>","hardware_batch":"HW2026Q3","stage":1,"quota_mode":"absolute","quota_value":2,"failure_threshold":0.2,"failure_min_sample":5}' ...
curl -X POST localhost:8080/api/admin/batches/<id>/action -d '{"action":"activate"}'
#   动作：activate / pause / halt / resume(熔断后需 force:true) / complete
#   pause、halt 沿 parent_id 向后续阶段级联；activate/resume 只作用本阶段

# 3. 终端侧（每次联网唤醒执行）
curl -X POST localhost:8080/api/device/register -d '{"id":"term-1","model":"term-x1",...}'
curl -X POST localhost:8080/api/device/check-in -H 'X-Device-Id: term-1' -H 'X-Root-Version: 1' \
     -H 'X-Notary-Tree-Size: 2'
#   offered=true 时返回分块清单（每块 offset/size/sha256）+ 签名发布信封
#   + offer.notary（成员见证 + 签名检查点 + 自 X-Notary-Tree-Size 以来的连续见证）；
#   trust.root_chain 携带设备缺失的根链链接（离线期间的轮换一次补齐）
curl 'localhost:8080/api/device/artifacts/<img>/chunks/0?assignment_id=<a>' -H 'X-Device-Id: term-1'
curl -X POST localhost:8080/api/device/events -H 'X-Device-Id: term-1' \
     -d '{"assignment_id":"<a>","event_type":"installed","idempotency_key":"<每设备每里程碑唯一>","payload":{...}}'

# 4. 公证层：账本 / 检查点 / 疑点材料 / 观察禁区
curl localhost:8080/api/admin/notary/info         # 公证公钥 + 当前签名检查点
curl localhost:8080/api/admin/notary/tree         # 全部规范条目 + 全部签名检查点
curl localhost:8080/api/admin/notary/evidence     # 设备上报的疑点材料（按内容去重）
curl localhost:8080/api/admin/notary/quarantine   # 被永久置入观察禁区的机型
#   终端检测到公证异常时：POST /api/device/notary-evidence
#   {"kind":"checkpoint_root_mismatch|tree_shrank|consistency_proof_invalid|
#           inclusion_proof_invalid|checkpoint_signature_invalid",
#    "evidence":{...},"idempotency_key":"nev-<内容派生>"}
```

交互文档：<http://localhost:8080/docs>

## 设计要点（需求 → 机制）

### 1. 兼容性：型号 / 引导程序 / 当前版本
- 镜像声明 `model`、`min_bootloader`、`max_bootloader`、`version`
  （`app/versioning.py` 做数字/词段混合版本比较）。
- 领用时三重过滤：型号完全相等；引导程序落在闭区间；当前版本 ≠ 目标版本
  （已在目标版本的设备不重复升级）。不匹配的设备在活动激活时也看不到 offer。

### 2. 逐级放量（硬件批次 × 阶段 × 名额）
- `batches` 行 = 某活动面向某 `hardware_batch` 的一个灰度阶段，带 `stage`、
  `quota_mode(absolute|percent)`、`quota_value`、`parent_id`。
- 设备 check-in 时按 `stage` 升序领取**第一个仍有名额的 active 批次**；
  阶段名额互不借用，实现金丝雀→小流量→全量的逐级推进（运营也可显式建后续阶段）。
- 百分比名额按该硬件批次在册设备数实时折算。

### 3. 名额的 exactly-once（重复上线/并发不重占）
两道防线：
1. 服务端进程锁串行化“读计数 → 插 assignment”（`app/rollout.py` 的 `_claim_lock`）；
2. 数据库 UNIQUE(`device_id`,`campaign_id`) 兜底——多 worker/Postgres 下也不可能插入第二条。
  设备再次 check-in 命中既有 assignment，直接返回同一 offer，**永不产生第二个名额**。
- 名额计数包含 installed/failed/in-flight 全部台账行：**失败设备保留名额**，
  抖动重试的设备无法把名额“腾”给别人（有测试 `test_failed_devices_keep_their_seat`）。
- 扩规模建议：把进程锁换成 `SELECT … FOR UPDATE` 行锁 + 切 Postgres（代码注释中标出了位置）。

### 4. 分块、校验、断点续传
- 上传时镜像被切成固定大小块（默认 256 KiB，`CHUNK_SIZE`），每块单独 sha256，
  整块按 `<sha256(block)>.part` 内容寻址存储，附 `manifest.json`（整体 sha256 + 块清单）。
- check-in 返回每块 `{index, offset, size, sha256}`。终端（`client/__init__.py`）：
  - 本地按**块哈希**校验已下载内容，只有哈希不一致/缺失的块才重新请求——
    断电、半截写、旧垃圾都会被识别为重传；
  - 全部块齐后再校验**整包 sha256**，通过才允许进入刷写；
  - 断网随时退出，下次唤醒只拉未验证块（测试覆盖断 1 块、坏块重拉、多次断连）。
  块响应带 `immutable` 缓存头，可被 CDN/边缘缓存安全缓存。

### 5. 安装失败回滚 + 原因上报
- 终端 A/B 双槽：向非活动槽刷写；健康检查失败则把新槽标记 bad、启动旧槽，
  随后发 `failed`（带 `reason` 与 `rolled_back_to`）和 `rollback_complete`。
- 服务端记录 `fail_reason`（可在 `/api/admin/assignments` 查询），
  并把设备影子版本回置为上报的上一可启动版本。
- 设备状态机只允许单向前进：
  `assigned → downloading → downloaded → installing → installed | failed`
  （`app/models.py` 的 `ALLOWED_TRANSITIONS`），乱序/迟到回执返回 409。

### 6. 暂停/熔断的安全语义
以状态机为准，而不是“一刀切断流”（`check_in` / `authorize_chunk` / `record_event` 三处同一规则）：

| 设备所处阶段 | pause / halt 后行为 |
|---|---|
| assigned（尚未开始） | 不再 offer，块接口 409，禁止推进 |
| downloading / downloaded（**未进入安装**） | **不得继续**：check-in 告知 `batch_paused/halted`，块接口 409，`installing` 事件 409 |
| installing（**已写关键区**） | **必须安全收尾**：照常给 manifest/块，允许发 `installed` 或 `failed`+回滚，绝不被半途掐断 |

- `pause` 可恢复（resume）；`halt` 是熔断/急停，**resume 必须显式 `force:true`**。
- 运营 pause/halt 与自动熔断都会**沿阶段树级联**到所有非终态子阶段，停止整条放量路径；
  activate/resume 不级联，后续阶段仍需显式开启。

### 7. 失败率越阈自动停止扩散
- 每次收到终态回执（installed/failed）后重算该批次
  `failure_rate = failed / (installed + failed)`；
  当样本数 ≥ `failure_min_sample` 且失败率 **≥ 批次阈值**（每批次可配，默认 20%）时，
  自动把该批次及全部子阶段置为 halted，并把 halted 批次列表随回执返回，
  设备侧/运营侧立刻可见。
- 判定在同一事务、同一把锁内完成并先 `flush`，保证本次回执计入统计；
  未达最小样本时不误杀（测试覆盖 100% 但样本不足不熔断、阈值边界、级联）。

### 8. 回执幂等（重复回执零副作用）
- 每条回执必须带 `idempotency_key`；`device_events` 对
  UNIQUE(`device_id`,`idempotency_key`) 建唯一索引。
- 重放返回首次结果且 `duplicate:true`：**不迁移状态、不重计失败率、不新增事件行**。
- 终端侧每个里程碑（downloading/installing/installed/failed/…）持久化稳定 key，
  崩溃重启后重放同一 key；若本地状态视图滞后收到 409，会先重新 check-in
  同步权威状态再带新 key 处理，绝不“以为升级了/没升级”。
- `download_started`、`rollback_complete` 是纯遥测事件，不推动状态机，可安全重复。

### 9. 离线发布签名（进入关键区前的五项校验）
- 每个发布都有**确定性序列化**的签名元数据（规范化 JSON：键排序、紧凑分隔符），
  覆盖 `artifact_sha256 / model / version(显示版本) / security_counter / expires`；
  签名算法 ed25519，私钥永不接触服务（`app/trust.py` 同时被服务端与终端复用，
   canonicalization 不可能漂移）。
- 终端在 `installing`（关键刷写区）**之前**依次校验：信任链 → 签名 → 过期 →
  制品摘要 → 安全计数器。任何一步失败：不写槽、保留当前可启动槽，并上报
  `release_rejected` 回执（持久化在 `device_events`，设备端与运营端均可查询；
  回执 key 由拒绝内容派生，断网重试天然幂等去重）。
- 无有效签名发布的镜像**永不 offer**（check-in 返回 `no_signed_release`，失败闭合）。

### 10. 防回滚安全计数器
- 终端持久化"已接受的最高计数器"（`trust.json`，原子写），只接受
  `counter >= 已接受最高值` 的发布；接受后立即落盘，**进程重启不回退**。
- 服务端同样单调：同一型号的发布计数器只升不降（`counter_regression` 409），
  信任状态不可能被发布动作拉低。

### 11. 根密钥轮换（新旧根双重授权）
- 根元数据按版本链式推进：v1 自签名（设备首用信任，生产应在出厂时预置）；
  vN+1 必须同时携带 **vN 根密钥的授权签名** 和 **vN+1 根密钥的自承诺签名**。
- 长期离线的设备唤醒时，check-in 按 `X-Root-Version` 返回缺失的整段根链，
  设备逐节校验后**原子切换**（tmp + rename）；任何一环缺失/未授权/过期都失败闭合，
  中断后重试从旧状态重新收敛，绝不出现"半个信任状态"。
- 被吊销的签名密钥（根元数据里 `revoked:true` 或不再列出）签署的发布，
  设备端与服务端发布入口都会拒绝；切流后只被旧根签署的内容同样被拒绝。

### 12. 发布幂等（并发发布只有一个结果）
- `POST /roots`、`POST /releases` 都带 `idempotency_key`（唯一索引兜底）：
  同 key 同内容重放返回首次结果（`duplicate:true`）；同 key 不同内容 409。
- 同一 `(model, version)` 的发布内容唯一：不同内容冒名同一版本 → 409
  （`release_version_conflict` / `release_exists`）；根版本重写/跳号同样被拒绝。

### 13. 软件供应公证（Merkle 追加账本 + 签名检查点 + 观察禁区）
- **追加即公证**：`publish_root` / `publish_release` 在**同一个数据库事务**里完成
  业务行写入 + 规范条目（canonical JSON）追加到 Merkle 树尾 + 公证钥匙签署新检查点
  （`app/notarization.py`）。树结构为 RFC 6962 风格：叶 `SHA256(0x00‖entry)`、
  内部节点 `SHA256(0x01‖L‖R)`（`app/notary.py`，服务端与终端共用，编码不可能漂移）。
- **崩溃原子性**：强制杀进程只会留下"全部可见"或"全部不可见"——对外不存在
  "能领取但账本无记录"的中间态；持同一请求令牌重试，最终至多一项完整登记和
  一个树叶（叶索引即主键，是唯一性的持久兜底）。
- **领取时的两类见证**：offer 的 `notary` 段携带该发布叶子的**成员见证**（审计路径）
  和从设备上次记住的检查点（`X-Notary-Tree-Size` 头）到当前检查点的**连续见证**；
  两者都是 O(log n) 个哈希——休眠再久的设备也绝不传输全量历史。
- **先验证，再动盘，原子落盘**：终端依次校验检查点签名（公证公钥 TOFU 锚定）→
  树高不回缩 → 同高必同根 → 连续见证衔接 → 条目绑定发布信封 → 成员见证成立；
  全部通过才把 `{新检查点 + 领取结果}` 作为**一次 tmp+rename 原子写**落盘
  （`notary.json`），随后才允许下载/刷写。
- **观察禁区**：检测到同高不同根、树高缩小、历史无法衔接、见证字节被改或检查点
  签名无效时，终端把疑点材料 POST 到 `/api/device/notary-evidence`（幂等键由材料
  内容派生）；服务端按内容哈希去重（**同一材料反复提交只保存一份**）并把该机型
  **永久**置入禁区（`quarantined_models`，纯 DB 状态，进程重启后仍生效）。
  禁区语义与暂停/熔断同构：已进关键区（installing）的设备允许收尾并回执，
  其余设备的领取/块下载/状态推进全部被拒（`model_quarantined`）。
- 公证私钥落盘位置由 `NOTARY_KEY_PATH` 决定（默认随数据卷），生产应放 HSM/KMS；
  设备端只锚定公钥。

## 数据模型（`app/models.py`）

```
devices(id, model, hardware_batch, bootloader, current_version, last_seen)
images(id, model, version, min/max_bootloader, size, sha256, chunk_size, chunk_count)
campaigns(id, image_id, name)
batches(id, campaign_id, hardware_batch, stage, quota_mode/value,
        state[pending|active|paused|halted|complete],
        failure_threshold, failure_min_sample, parent_id)
assignments(id, device_id, campaign_id, batch_id,
            install_state, fail_reason, active_slot)   -- UNIQUE(device,campaign)
device_events(id, device_id, assignment_id, event_type, idempotency_key,
              from_state, to_state, payload)           -- UNIQUE(device,idempotency_key)
root_metadata(version, metadata_json, signatures_json,
              content_hash, idempotency_key)           -- 版本即主键，链式单调
releases(id, image_id, model, version, artifact_sha256, security_counter,
         expires_at, metadata_json, signatures_json, content_hash,
         idempotency_key)                              -- UNIQUE(model,version), UNIQUE(image)
notary_leaves(leaf_index, entry_type, ref_id, entry_json, leaf_hash)
                                                       -- 叶索引即主键：只追加，不改写
notary_checkpoints(tree_size, root_hash, signature)    -- 每个树高一行的签名检查点
notary_evidence(id, evidence_hash, device_id, model, kind, detail_json,
                idempotency_key)                       -- UNIQUE(evidence_hash)：材料去重
quarantined_models(model, reason, evidence_hash)       -- 机型即主键：永久禁区
```

## 验证矩阵

`docker run --rm fota-service:dev test -v` 或本地 `pytest -v`（51 项）：

| 关注点 | 测试文件 |
|---|---|
| 型号/引导窗口/版本过滤、块清单 | `tests/test_compatibility.py` |
| 绝对/百分比名额、阶段顺序、重复 check-in、失败占名额 | `tests/test_rollout_quota.py` |
| 断块续传、坏块重拉、多次断连 | `tests/test_resume.py` |
| 暂停拦截、关键区收尾、级联、force 恢复 | `tests/test_pause_halt.py` |
| 越阈熔断、级联停扩散、阈值边界、原因留档 | `tests/test_failure_halt.py` |
| 回执重放、8 路并发重复上线、名额竞争、乱序拒绝 | `tests/test_idempotency.py` |
| 签名发布安装、篡改元数据/块拒绝、过期/吊销/计数器回滚、多代轮换、缺环失败闭合、轮换中断收敛、并发发布幂等、退休根拒绝、暂停门保持 | `tests/test_signing.py` |
| Merkle 数学自检、首登成员见证+切槽、休眠设备对数追赶、翻转见证/抽历史/小树高/分裂视图禁区、疑点去重、崩溃无孤儿无双叶、6 并发同令牌一叶、禁区下动盘收尾 | `tests/test_notary.py` |

真实 HTTP 进程端到端（非 TestClient）也已验证：断 1 块后唤醒只拉剩余块、
暂停中途唤醒返回 `batch_paused`、恢复后续传并安装、2/2 失败自动熔断并级联阶段 3、
失败设备影子版本回滚、安装成功版本跨进程重启保持；
签名链路同样过了真实进程验证：种子根链 + 签名发布安装、篡改拒绝回执、
服务端重启后根链/发布/回执/设备信任状态全部保持、离线轮换 v1→v2 一次唤醒收敛。
公证链路的真实进程验证（`scripts/e2e_notary.py`，起真实 uvicorn + 真实设备进程）：
种子发布带可验证成员见证完成切槽、分裂视图证据使机型进禁区且证据去重、
**服务进程重启后禁区与账本原样保持**、新领取持续被拒。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `DATABASE_URL` | 本地 sqlite | SQLAlchemy URL；生产建议 Postgres |
| `STORAGE_ROOT` | `.data/artifacts` | 分块镜像存储目录（compose 挂卷 `/data`） |
| `CHUNK_SIZE` | 262144 | 块大小（字节） |
| `FAILURE_THRESHOLD` / `FAILURE_MIN_SAMPLE` | 0.2 / 3 | 批次默认熔断阈值与最小样本 |
| `SEED_DEMO` | false | 启动时种入一个演示镜像 + 金丝雀批次（compose 开启） |
| `DEMO_KEYS_PATH` | `<STORAGE_ROOT>/../demo_keys.json` | 演示用签名密钥对的落盘位置（仅 demo；生产私钥应离线保管） |
| `NOTARY_KEY_PATH` | `<STORAGE_ROOT>/../notary_key.json` | 公证签名钥匙的落盘位置（生产应放 HSM/KMS，设备只锚定公钥） |

## 生产化备注（本实现刻意留出的边界）

- 鉴权：管理端应加运营 SSO/角色，设备端用设备证书/签名令牌（当前为裸 header，便于演示）。
- 信任根引导：设备首用信任（TOFU）自签名的 root v1；生产应在出厂时预置 root v1 公钥，
  并用 HSM/KMS 保管根私钥，发布签名保持离线。
- 公证钥匙同理：生产放 HSM/KMS 且只出公钥；检查点可在设备间 gossip 交叉验证，
  或镜像到独立见证方（witness cosigning）以缩短分裂视图的检测时延。
- 规模：单 worker + 进程锁 + sqlite 用于可复现演示；多实例部署切 Postgres，
  将名额领取改为批次行 `SELECT … FOR UPDATE`，账本叶索引用计数器行同样加行锁，
  子树哈希可做 tile 缓存（叶表已含全部重建材料），块对象放 S3/CDN
  （块内容寻址且 immutable，可直接缓存）。
- 回执可加老化归档；`assignments` 建议按 (campaign, device) 分区。
