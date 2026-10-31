# ColorOS 助手 OTA 协议逆向研究

> **无需手机、无需官方客户端 —— 纯 Python 直连 OPPO 服务器获取刷机包下载链接的完整协议逆向**
>
> 研究对象：ColorOS助手（升级降级工具）V1.3.20 / V1.4.42 全协议栈
> 最终成果：**版本欺骗技术**——声称任意旧版本号，从 OPPO 制品库骗出全量 OTA 刷机包（含 VAB 元数据）

---

## ⚠️ 免责声明

本研究仅用于**个人设备固件获取与安全研究**（Windows PC 端协议分析、自有设备互操作性研究）。所有实验均在研究者本人拥有的设备与账号上进行。请勿用于非法用途。刷机有风险，降级会清除数据，请自行承担。

---

## 🏆 成果速览

| 能力 | 状态 | 说明 |
|---|---|---|
| 升级包纯协议查询 | ✅ | 无需会话，声称任意版本骗取全量 OTA 包 |
| **版本欺骗** | ✅ | 声称旧版本 → 服务器吐出"旧→新"全量刷机包 |
| 工具自更新接口复现 | ✅ | MD5 签名算法破解（含硬编码盐） |
| 降级包查询协议还原 | ✅ 95% | cipherInfo 信封格式完整还原；会话凭据依赖手机在线 |
| PC↔手机握手算法 | ✅ | ECDSA P-256 + SHA256，真实报文 100% 验签通过 |
| 密码学原语纯 Python 实现 | ✅ | AES-256-GCM / RSA-PKCS1v15（均过标准向量） |
| deviceId（duid）溯源 | ✅ | MSA OAID‖GUID 拼接，出厂注册进 OPPO 设备库 |

**实战战果**（PJD110 一加 12 / PLZ110 等真机验证）：

| 包 | 获取方式 | 链接形态 |
|---|---|---|
| ColorOS 15.0.2 全量包（C.82） | 版本欺骗（声称 C.12） | `gauss-*.allawnfs.com` 无签名直链 ✅ |
| ColorOS 15.0.2 降级包（C.1840） | query-v3 真实会话 | `downgradefs.coloros.com` 无签名直链 ✅ |
| ColorOS 16.1.0 全量包（F.57/A.37） | 版本欺骗 | `downloadCheck` 签名链 ✅（带设备头流式下载，支持 Range） |

---

## 1. 系统架构

```
┌─────────────┐  adb forward+socket   ┌──────────────────┐
│ ColorOS助手  │◄─────────────────────►│ 手机 OTA 服务 APK  │
│ (Electron)   │   cmdId 40001 握手     │ (com.color.       │
│              │   ECDSA P-256 认证     │  otaassistant)    │
│  SocketConnect.dll (C++)                    │
│   ├─ PackageManager  ──── HTTP ────┐         │
│   ├─ OtaSocketModel (cmdId 40001)  │         │
│   └─ NodeImpl.node (JS桥)          │         │
└────────────────────────────────────┘         │
        │ Utils.dll (libcurl/OpenSSL + Json)   │
        ▼                                      ▼
┌──────────────────────────────────┐  ┌──────────────────┐
│ downgrade.coloros.com            │  │ OPPO 设备库       │
│  /upgrade/query   (无需会话)      │  │ (duid 注册表)     │
│  /downgrade/query-v3 (需会话)     │  └──────────────────┘
│ diagnostic-tool.coloros.com      │
│  /upgrade/tool    (自更新)        │
│ component-ota-cn.allawntech.com  │  ← 包下载（2种形态）
│ gauss-*.allawnfs.com             │  ← 包下载（无签名直链）
│ downgradefs.coloros.com          │  ← 降级包（无签名直链）
└──────────────────────────────────┘
```

**关键结论**：所有"智能逻辑"都在 **PC 端 C++**（SocketConnect.dll，导出 90 个符号）；手机端 APK（OTA_NORMAL）只是 PC↔手机消息服务器，**从不直接联系 OTA 服务器**；手机搬家 APK（backuprestore）是独立体系（heytapmobi 域），与刷机包无关。

---

## 2. 端点清单（自 SocketConnect.dll 字符串表）

| 端点 | 用途 | 鉴权 |
|---|---|---|
| `POST {GrayscaleManageUrl}/upgrade/tool` | 助手自更新检查 | MD5 签名（盐硬编码） |
| `POST {DowngradeServerUrl}/upgrade/query` | **升级包查询（无会话！）** | deviceId 须已注册 |
| `POST {DowngradeServerUrl}/downgrade/query-v3` | 降级包查询 | cipherInfo 信封 + 会话 |
| `POST {DowngradeServerUrl}/downgrade/cancel-v3` | 去除黑名单/重推 | 同上 |
| `POST {DowngradeServerUrl}/downgrade/feedback-v3` | 降级结果反馈 | 同上 |
| `POST {DowngradeServerUrl}/downgrade/apk` | 降级 APK 信息 | 明文 |
| `POST {DFSUrl}/...` (LoginServer) | 插件清单 QueryAllPlugins | 明文 |
| `GET component-ota-cn.allawntech.com/downloadCheck?...` | 签名包下载校验 | 网关绑定（见 §7） |

配置来源 `config.ini`：`DowngradeServerUrl_cn=https://downgrade.coloros.com`（**升级与降级共用此基址**，升级路径为 `/upgrade/query`）。

---

## 3. 协议 1：助手自更新检查（签名算法破解）

```
POST https://diagnostic-tool.coloros.com/upgrade/tool
Content-Type: application/json; charset=UTF-8

{"ip":"...","mac":"...","sign":"<MD5>","timestamp":"<unix秒>",
 "toolType":"coloros_assist_tool","toolVersion":"V1.3.20"}
```

**签名算法**（自 `SocketConnect.dll` file@0x527f4 盐字符串 + 真实日志样本验证命中）：

```
sign = MD5( "ip=<ip>&mac=<mac>&timestamp=<ts>&toolType=<t>&toolVersion=<v>"
            + "XEdEbJ0h3MsefsfvdHgTj689lmivNSvlgEb" )     ← 硬编码盐
```

响应：
```json
{"code":200,"data":{"updateStatus":1,
 "downloadUrl":"https://dfs-serverauto-cn.allawnfs.com/dfs/26/10/12/xxx.exe",
 "fileMd5":"ca357c...","fileName":"ColorOSAssistSetupV1.4.42.exe","version":"V1.4.42"}}
```

---

## 4. 协议 2：升级包查询（纯协议可用）⭐

`POST https://downgrade.coloros.com/upgrade/query`

**请求头**（V1.4.42 手机端 `RequestUtil.java` 溯源的 23 个字段）：

```
language: zh-CN        romVersion: PLZ110_11_A.31     androidVersion: Android16
colorOSVersion: ColorOS16.1.0    infVersion: 1        operator: (空)
trackRegion: CN        uRegion: CN                    model: PLZ110
mode: manual           nvCarrier: 10010111            pipelineKey: ALLNET
version: 2             deviceId: <64hex duid>          marketName: <机型名>
prjNum: 25821          channel: pc                    otaVersion: <完整OTA版本>
first_api_level: 36    sn16: (可空)                   userid: oplus-ota|<ver>
ts: <毫秒时间戳>        guid: <MD5,可为空串MD5>          Content-Type: application/json; charset=UTF-8
```

**请求体**：

```json
{"components":[ 8 个组件... ],
 "mode":0,"time":<毫秒>,"isRooted":"0","type":"0","registrationId":"",
 "securityPatch":"2026-06-01","securityPatchVendor":"2026-06-01",
 "deviceId":"<64hex duid>"}
```

8 组件 = `system_vendor, my_product, my_heytap, my_stock, my_region, my_carrier, my_bigball, my_manifest`。
各组件版本含独立构建时间戳与 8 位 hex 尾（**实测尾部 hash 不校验**，但结构需自洽）。

**响应**（code=200 时）：

```json
{"code":200,"data":"{\"parent\":\"ota\",\"components\":[{
  \"componentId\":\"my_manifest_...\",\"componentVersion\":\"...\",
  \"componentPackets\":{\"size\":\"9526156006\",
    \"manualUrl\":\"https://gauss-componentotacostmanual-cn.allawnfs.com/...zip\",
    \"url\":\"https://gauss-compotacostauto-cn.allawnfs.com/...zip\",
    \"md5\":\"...\",\"type\":\"1\",\"vabInfo\":{...VAB刷机元数据...}}},
 \"otaVersion\":\"...\",\"securityPatch\":\"...\"}"}"}
```

### 4.1 ⭐ 版本欺骗（核心成果）

**服务器完全信任请求声称的版本**。声称设备停留在旧版本 → 返回"旧→新"的全量 OTA（含 `payload.bin`、`payload_metadata.bin`、VAB 校验哈希——可直接刷写的刷机包）：

```
声称 F.23   →  返回 F.57 全量包 (PJD110)
声称 C.12   →  返回 C.82 全量包 (PJD110, ColorOS 15.0.2, gauss 无签名直链)
声称 A.10   →  返回 A.37 全量包 (PLZ110, 9.17GB)
```

实验约束（实测得出）：
- `deviceId` 必须是**已注册**真机的 duid（随机/全零 → `1004`）
- 声称版本的 `securityPatch` 建议按"构建月 05 日"规则伪造（错配 → `2400`）
- 组件尾部 hash8、`.97` 段**不校验**（可填 `00000000`）
- `mode=1` → `2426`（仅支持手动模式）

### 4.2 deviceId（duid）溯源

duid = **MSA OAID(32hex) ‖ GUID(32hex)** 拼接（64 hex，双 UUIDv4 结构——版本位/变体位完全吻合）：

```java
// OTA_NORMAL.apk → r/b.java (RequestUtil)
r1.a.e(context);                    // StdIDSDK 初始化
String duid = r1.a.d(context);      // MSA OAID ‖ GUID
String guid = new IdProviderImpl().getOpenid(context, "GUID");
// duid 为空时回退 64 个 '0'；guid 为空时上层填 MD5("")
```

duid 由 MSA SDK（移动安全联盟）在设备上生成、**出厂/首联时注册进 OPPO 设备库**——纯算法无法伪造（服务器 `1004` 拒绝未注册 duid）。**获取途径：让 ColorOS助手连接该设备一次，档案自动落入日志**（`OnSocketRecvDeviceInfoAck` 行）。

---

## 5. 协议 3：降级包查询 query-v3（信封 + 会话）

### 5.1 cipherInfo 信封（进程内存取证获得真实格式）

```
cipherInfo: {"downgrade-server":{"negotiationVersion":1636449646204,
             "protectedKey":"<b64(RSA(pub, 会话凭据))>",
             "version":"<unix秒>"}}
```

- **根键 = 场景名**：`downgrade-server`（降级）/ `dfs-ms`（埋点，证书场景）——Jackson 反序列化为 `HashMap<String, ProtectedKeyVO>`
- `ProtectedKeyVO`（Jackson 类型探测）：`{negotiationVersion, version, salt, info}`，downgrade-server 场景实际使用 `{negotiationVersion: int64, protectedKey: str, version: str}`
- `negotiationVersion` = **毫秒时间戳密钥版本**，DLL 内嵌版本池：`1636449646204 / 1631593594729 / 1633220648060 / 1713486352080 / 1706244667088`（.rdata 常量表，每版本对应一把内嵌 RSA-2048 公钥）
- 客户端流程（0x23080→0x232d0）：`aesGenKey(32B key) + aesGenKey(12B iv)` → `toBase64(key)` → `rsaEncrypt(pub, b64(key), padMode=1)` → `toBase64(密文)` → 三字段 JSON

### 5.2 请求体（deviceId 加密）

```json
{"deviceId":{"cipher":"<b64(AES-256-GCM(key,iv12,dev64hex)||tag16)>","iv":"<b64(iv12)>"},
 "otaVersion":"...","model":"...","androidVersion":"...","colorosVersion":"...",
 "nvCarrier":"...","prjNum":"...","serialNo":"..."}
```

### 5.3 会话依赖（为什么纯离线不行）

- 重放完整真实报文 → 稳定 `AES decrypt error`（排除时效/rid/cookie/UA/请求头全部变量）
- 自造信封 → `decrypt from crypto-dist-domain error`（服务器 crypto-dist 域校验）
- APK 异常类 `SessionExpiredException` / `SceneNotFoundException` + 实验证据 → **protectedKey 内是"协商凭据"而非裸密钥**，服务器查会话表；会话在手机连接、助手与手机 OTA 服务握手时建立，数分钟内过期
- **这是协议的安全设计**：防止任意枚举他人设备固件

### 5.4 响应与验签

```json
{"code":200,"data":{"metaData":"<b64 RSA签名>",
 "downgradeVoList":[{"downloadUrl":"https://downgradefs.coloros.com/...zip",
   "otaVersion":"10010111_22825_PJD110_11_C_OTA_1840_all_Qlg912",
   "colorosVersion":"ColorOS15.0.2","fileSize":9526156006,"fileMd5":"..."}]}}
```

`metaData` 用**内嵌公钥[0]**（`rsaVerifySha256`）验签；`checkData = "deviceId:<sn>userOtaVersion:<ota>"`。

---

## 6. PC↔手机本地握手（cmdId 40001）

```json
{"cmdId":40001,"createTime":"<微秒>","needAck":true,"uuid":"<GUID>",
 "extraInfo":"{\"pubKey\":\"<SPKI P-256 b64>\",\"signData\":\"<ms><16随机字符><微秒>\",
              \"signValue\":\"<DER ECDSA>\",\"verifyPass\":true}"}
```

- **signValue = ECDSA-P256 + SHA256(signData)**，DER 编码 —— 4 组真实报文 100% 验签通过（`openssl`/Node crypto 对照）
- 双方各生成临时 P-256 密钥对互验后 **ECDH**（OpenSSL NID 408 = prime256v1，反汇编确认 `mov edx, 0x198`）
- **会话 AES 密钥 = SHA256(共享密钥) 的 hex 前 32 字符（16 字节）** → AES-128 会话加密（deviceId 等字段 `{"cipher","iv"}` 形态）

---

## 7. 包下载的两种形态

| 形态 | 特征 | 可下载性 |
|---|---|---|
| **gauss 桶直链** | `gauss-componentotacostmanual-cn.allawnfs.com/remove-<id>/component-ota/YY/MM/DD/<md5>.zip` | ✅ 无签名、无时效、任意工具下载 |
| **component-ota 签名链** | `component-ota-cn.allawntech.com/downloadCheck?c=&p=&d=&g=&id=&s=` | ✅ **请求必须携带完整设备请求头**（服务器将签名链接与设备绑定校验；无头 → `2306`；带头 → `206` 流式返回包本体，支持 Range 断点续传） |
| **downgradefs** | `downgradefs.coloros.com/downgrade/YY/MM/DD/<md5>.zip` | ✅ 无签名直链 |

`downloadCheck` 参数 `c/p/d/g/id/s` 为查询时动态签发（`c`=32hex 每次不同）。**关键发现：裸请求 → `2306`；携带与查询相同的完整设备请求头 → `206 Partial Content`，直接流式返回 OTA ZIP 本体**（已实测 `Range: bytes=0-2047` 拿到 `PK` 魔数与 `payload.bin` 目录）。签名链接与设备请求头绑定校验。

---

## 8. 服务器证书机制（certVersion）

- 启动时 `LoginServer::GetPubKey` 下发：`{"certVersion":1652408536857, "encryptScene":"dfs-ms", "publicKey":"<RSA-2048 SPKI>", "cert4Sign":"<X.509 证书>"}`
- cert4Sign 证书：OPlus Service CA E1 签发，**有效期起点 2022-05-13 = certVersion 毫秒时间戳**（2022-05-13）
- 该密钥对属于 **dfs-ms 场景**（埋点/DFS 消息加密，libTHS.dll 使用），与 downgrade-server 场景的密钥池相互独立
- V1.4.42 起 `sdkCfg.json`（本地公钥配置）被删除，改为服务器动态下发——密钥轮换不再需要发版

---

## 9. 错误码表（实测归纳）

| 码 | 含义 |
|---|---|
| `1004` | duid 查询 guid 为空 —— deviceId 未注册/不合法 |
| `2004` | artifactV1Result is empty —— 请求通过，制品库无匹配（通常=已最新或无包） |
| `2107` | 设备状态真实但无可用升级包（常=包已下架） |
| `2306` | downloadCheck 网关绑定鉴权失败 |
| `2400` | 组件清单校验失败（设备档案与请求的 prjNum/组件冲突） |
| `2426` | mode 不支持（仅手动 mode=0） |
| 500 `cipherInfo in header is not allowed empty` | 缺 cipherInfo 头 |
| 500 `parse cipher json error` | body 的 cipher 字段解析失败 |
| 500 `AES decrypt error` | 信封 RSA 通过但 AES 会话解密失败（会话过期/重放） |
| 500 `decrypt from crypto-dist-domain error` | crypto-dist 域解密失败（凭据/密钥不匹配） |

---

## 10. 密码学原语（纯 Python 实现，均过标准验证）

| 原语 | 参数 | 验证方式 |
|---|---|---|
| AES-256-GCM | 12B IV，输出=密文‖tag16 | NIST GCM TC14 与 Node crypto 逐字节一致 |
| RSA-PKCS1v15 | 2048bit，e=65537 | 真实 blob 重放被服务器正确解密 |
| ECDSA-P256 | SHA256，DER | 4 组真实握手报文验签通过 |
| ECDH-P256 | prime256v1 (NID 408) | 反汇编 + 结构吻合 |
| KDF | `AES key = SHA256(shared)[0:32] hex` | 反汇编 `GetHash(data,len,1)`+截断 |
| MD5 签名 | 盐 `XEdEbJ0h3MsefsfvdHgTj689lmivNSvlgEb` | 真实日志样本命中 |
| HashMethod 枚举 | 0=MD5, 1=SHA256 | 反汇编 GetHashBuf 分支 |

内嵌 RSA-2048 公钥（两版 DLL 4 把完全一致 + 1 把动态下发）：`AnroYy...`(响应验签) / `qxCK...` / `meQz...` / `i4mA...` / 动态 `qIvz...`（cert4Sign 证书，OPlus Service CA E1）。

---

## 11. 工具使用

```
python get_ota_link.py                          # 展示已知直链 + 自更新检查 + 设备档案查询
python get_ota_link.py --list-profiles          # 从助手日志自动提取设备档案（任意机型）
python get_ota_link.py --model PJD110           # 指定机型查询
python get_ota_link.py --update-check           # 仅查助手官方最新版
python get_ota_link.py --v3                     # 降级查询（实验性，需会话）
python get_ota_link.py --spoof <otaVersion>     # ⭐ 版本欺骗查询（见 README §4.1）
```

- 档案自动提取：ColorOS助手连接过任意设备一次后，其日志（`%APPDATA%\coloros-assist\logs\`）即含该设备完整档案，工具自动解析（多设备并存，按 `机型|otaVersion` 分组）
- **注意**：公开版已将内置示例 deviceId 脱敏为占位符——请按 §4.2 方法填入自己设备的值

---

## 12. 逆向方法论（可复用）

1. **Electron 应用**：`resources/app.asar` 自定义解析器解包 → 定位原生模块 `NodeImpl.node` 与 DLL 分工
2. **PE 反汇编**：`pefile` + `capstone`，`.pdata` 函数边界 + 递归遍历（规避跳转表数据岛）+ IAT 动态标注
3. **日志考古**：DEBUG 级日志完整记录握手/请求/响应报文——直接提取真实样本
4. **签名算法黑盒验证**：从日志取 `(pubKey, signData, signValue)` 三元组，标准库验签 → 算法实锤（免去全部静态分析）
5. **Jackson 报错预言机**：利用服务器 JSON 反序列化错误信息（reference chain / 字段类型不匹配）远程枚举 VO 类的字段名与类型
6. **进程内存取证**：`ReadProcessMemory` 全堆扫描，直接提取运行时构造的真实报文（突破静态分析盲区）
7. **错误码差分**：单变量变异（版本号/组件/头）观察业务码演进，定位服务器校验逻辑

---

## 13. 已知限制

- query-v3 的会话凭据依赖手机在线协商，纯离线不可用（协议安全设计）
- `downloadCheck` 签名链的 2306 网关鉴权未破解（gauss/downgradefs 直链形态不受影响）
- 升级查询的组件清单需与设备档案自洽（deviceId 主导，服务器按库内设备档案校验）
- 降级包存在性由 OPPO 按机型白名单配置（如 PJD110 配了 "waffle 降级包测试"，多数机型无配置）

## 14. 文件结构

```
├── README.md                 # 本文档
├── get_ota_link.py           # 纯 Python 工具（标准库，含全部已还原协议）
└── docs/
    └── protocol-samples.md   # 脱敏真实报文样本
```

---

*研究时间线：2026-10-30 ~ 2026-10-31（两天，从 .lnk 快捷方式分析到全协议栈还原与版本欺骗落地）*
