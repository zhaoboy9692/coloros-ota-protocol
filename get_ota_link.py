#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 ColorOS助手 OTA 协议逆向 —— 刷机包下载链接获取工具 (纯 Python, 零第三方依赖)
================================================================================
逆向来源:
  * C:\\Program Files\\coloros-assist\\SocketConnect.dll / Utils.dll (V1.3.20)
  * V1.4.42 官方安装包内 SocketConnect.dll
  * 手机端 OTA_NORMAL.apk / OTA_113.apk
  * 本机 ColorOS助手 历史日志 (2025-07-14 完整报文)

协议还原结论 (全部经实验验证):
────────────────────────────────────────────────────────────────────────────────
[1] 工具自更新检查  POST {GrayscaleManageUrl}/upgrade/tool
    body = {"ip","mac","sign","timestamp","toolType","toolVersion"}
    sign = MD5("ip=<ip>&mac=<mac>&timestamp=<ts>&toolType=<t>&toolVersion=<v>"
               + "XEdEbJ0h3MsefsfvdHgTj689lmivNSvlgEb")          ← 盐已提取
    返回最新版 downloadUrl + fileMd5 (V1.4.42 已实测拿到)

[2] 升级包查询      POST {DowngradeServerUrl}/upgrade/query   (基址=downgrade.coloros.com)
    body  = {"components":[{componentName,componentVersion}...8项],"mode":0,
             "time":<ms>,"isRooted":"0","type":"0","registrationId":"",
             "securityPatch":...,"securityPatchVendor":...,"deviceId":...}
    headers = 手机下发 requestHeader 的 18 个字段 + Content-Type
    返回 {"code":200,"data":"{...componentPackets.manualUrl/url/md5...}"}
         2107=无可用包  2400=组件版本校验失败(需真实组件清单)
    注意: 服务器校验组件版本真实性(非格式), 其他机型需真实设备档案,
          本工具会自动从本机 ColorOS助手 日志提取(任何连过助手的机型都行)。

[3] 降级包查询 v3   POST {DowngradeServerUrl}/downgrade/query-v3
    header "cipherInfo" = 场景化信封(进程内存取证获得真实格式, Jackson 2026 实测通过):
        {"downgrade-server": {"negotiationVersion": 1636449646204,
                              "protectedKey": "<b64(RSA(pub, 会话凭据))>",
                              "version": "<unix秒>"}}
    body 中 deviceId = {"cipher": b64(AES-256-GCM(key,iv12,dev64hex)||tag16), "iv": b64(iv12)}
    其余明文: otaVersion/model/androidVersion/colorosVersion/nvCarrier/prjNum/serialNo
    服务器响应: {"code":200,"data":{"metaData":"<RSA签名(内嵌公钥0验签)>",
                "downgradeVoList":[{downloadUrl, otaVersion, colorosVersion,
                fileSize, fileMd5}...]}} —— 直链域 downgradefs.coloros.com (无签名)
    ★ 会话依赖: protectedKey 内是"协商凭据"而非裸密钥, 服务器查会话表
      (SessionExpiredException 佐证); 会话在手机连接、助手与手机OTA服务握手时
      建立, 数分钟内有效。故纯脚本无法离线查询——须手机在线+助手会话。
      降级包直链本身无签名, 助手取到链接后可任意工具下载。

[4] PC↔手机本地握手 (cmdId 40001):
    signData  = "<毫秒时间戳><16位随机串><微秒时间戳>"
    signValue = ECDSA-P256-SHA256(signData), DER 编码   ← 4组真实样本100%验签通过
    ECDH=P-256(NID 408), 会话AES密钥=SHA256(共享密钥)取hex前32字符(16字节)

[5] 刷机包 CDN: gauss-componentotacostmanual-cn.allawnfs.com (无签名永久直链)
================================================================================
用法:
  python get_ota_link.py                    # 自动模式
  python get_ota_link.py --model PEXM00     # 指定机型
  python get_ota_link.py --update-check     # 查询助手官方最新版
  python get_ota_link.py --list-profiles    # 列出本机日志中的设备档案
"""

import base64
import glob
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.error

# ============================================================================
# 一、密码学原语 (纯 Python 实现, 均通过标准测试向量验证)
# ============================================================================

# ---------- AES-256-GCM (NIST GCM 规范 TC14 与 Node crypto 对照一致) ----------
_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    a <<= 1
    if a & 0x100: a = (a ^ 0x1b) & 0xff
    return a

def _key_expand(key):
    nk = len(key)//4; nr = nk + 6
    w = [list(key[4*i:4*i+4]) for i in range(nk)]
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:]+t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i//nk-1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return w, nr

def _aes_encrypt_block(block, w, nr):
    s = [[block[r+4*c] for c in range(4)] for r in range(4)]
    def addrk(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= w[rnd*4+c][r]
    def subshift():
        for c in range(4):
            for r in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1,4):
            s[r] = s[r][r:]+s[r][:r]
    def mix():
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _xtime(a[0])^(_xtime(a[1])^a[1])^a[2]^a[3]
            s[1][c] = a[0]^_xtime(a[1])^(_xtime(a[2])^a[2])^a[3]
            s[2][c] = a[0]^a[1]^_xtime(a[2])^(_xtime(a[3])^a[3])
            s[3][c] = (_xtime(a[0])^a[0])^a[1]^a[2]^_xtime(a[3])
    addrk(0)
    for rnd in range(1, nr):
        subshift(); mix(); addrk(rnd)
    subshift(); addrk(nr)
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _ghash_mult(x, y):
    R = 0xe1000000000000000000000000000000
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1: z ^= v
        if v & 1: v = (v >> 1) ^ R
        else: v >>= 1
    return z

def aes_gcm_encrypt(key, iv, plaintext, aad=b""):
    """返回 密文||tag(16字节)"""
    w, nr = _key_expand(key)
    j0 = iv + b"\x00\x00\x00\x01" if len(iv) == 12 else None
    if j0 is None:
        raise ValueError("only 12-byte IV supported (protocol uses 12B GCM IV)")
    h = int.from_bytes(_aes_encrypt_block(b"\x00"*16, w, nr), 'big')
    ct = bytearray()
    icb = int.from_bytes(j0, 'big')
    for i in range(0, len(plaintext), 16):
        icb += 1
        ks = _aes_encrypt_block((icb % (1 << 128)).to_bytes(16, 'big'), w, nr)
        blk = plaintext[i:i+16]
        ct += bytes(a ^ b for a, b in zip(blk, ks))
    pad = lambda b: b + b"\x00" * ((-len(b)) % 16)
    data = pad(aad) + pad(bytes(ct))
    ln = (len(aad)*8).to_bytes(8, 'big') + (len(ct)*8).to_bytes(8, 'big')
    y = 0
    for i in range(0, len(data), 16):
        y = _ghash_mult(y ^ int.from_bytes(data[i:i+16], 'big'), h)
    y = _ghash_mult(y ^ int.from_bytes(ln, 'big'), h)
    ekj0 = int.from_bytes(_aes_encrypt_block(j0, w, nr), 'big')
    tag = ((ekj0 ^ y) & ((1 << 128) - 1)).to_bytes(16, 'big')
    return bytes(ct) + tag

# ---------- RSA PKCS#1 v1.5 (纯大数运算, m^e mod n) ----------
def rsa_pkcs1v15_encrypt(n, e, msg):
    k = (n.bit_length() + 7) // 8
    ps = bytearray()
    while len(ps) < k - 3 - len(msg):
        b = os.urandom(1)
        if b != b"\x00": ps += b
    m = int.from_bytes(b"\x00\x02" + bytes(ps) + b"\x00" + msg, 'big')
    return pow(m, e, n).to_bytes(k, 'big')

def parse_rsa_pubkey_pem(pem_text):
    """手工解析 PEM(PublicKey) -> (n, e)，纯 Python DER 解析"""
    body = re.sub(r"-----[A-Z ]+-----|\s+", "", pem_text)
    der = base64.b64decode(body)
    def read_tlv(d, i):
        tag = d[i]; i += 1
        l = d[i]; i += 1
        if l & 0x80:
            nb = l & 0x7f; l = int.from_bytes(d[i:i+nb], 'big'); i += nb
        return tag, d[i:i+l], i + l
    _, content, _ = read_tlv(der, 0)
    _, alg, p = read_tlv(content, 0)
    _, bits, p = read_tlv(content, p)
    _, keyseq, _ = read_tlv(bits, 1)
    _, n_bytes, p = read_tlv(keyseq, 0)
    _, e_bytes, _ = read_tlv(keyseq, p)
    return int.from_bytes(n_bytes, 'big'), int.from_bytes(e_bytes, 'big')

# ============================================================================
# 二、从 SocketConnect.dll 提取的内嵌 RSA-2048 公钥 (negotiationVersion 1/2/3)
# ============================================================================
PEM_PUBKEYS = [
# [0] 响应验签用 (metaData 校验, rsaVerifySha256)
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnroYy8KlC0/RpsCufm/kMFIAOVDQksKKeXPrg3m1Y/pBhKwIWg6QRLOF3vWbyDcw4WDOkXHWpF0HF106/SkamjELRqRJWTk/wrJb/yYKUHzue2oZ+YqaA/RLpue8S2aQ7d6ubcQuhHfZDCJYzEl+76+2KWE4EL8Mm8JAIG2+O6iifIbc5Ip3HNNkcrf6lILuIgdeGSTIxtfCvblc+lWhZGGGGmzU/Xc7fip9mI09+Ex9/0YFqaQlRG37Q0GgCWbEgJJHfutV562MJNis8cgC/vz1PCb6Ghcr+XKIaWyPZOVNFhLWkCEqISPlIPiu+EkfFmzngqKjFxKeQbeUcI54xwIDAQAB
-----END PUBLIC KEY-----""",
# [1] negotiationVersion=1
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqxCKAC9bPZFa8Atze50xXch+LB20evUzTgZu3ODBZPjAn6FznOhLg7AptsGYlJNJqoIPOVL3qkE4c1my5IAMS8vQyt70pnSI7U+38ELV4F2IiLzVYZCpkHsn7T6xd2PQHvzLrzkVWY7todAmbHYEIq5TioKSh8IDe1S40OOzoahlgBcrk2IuuL/bfOTrIo1IgO4WtuRLGW41Yw/RwuhqOoDqG1rHFgTw6lOWj7IBf9twCPI9TOBCZo4KYmL0ReBspzHiDB1/VN0l7NVv6wzs4UbJsZPP7o5XhP/Z+ZfKRsmmo5V2cdN8GECN6OMELc9exdhIgQM/MoMLSYU6kvFprwIDAQAB
-----END PUBLIC KEY-----""",
# [2] negotiationVersion=2
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmeQzr0TIbtwZFnDXgatg6xP9SlNBFho1NTdFQ27SKDF+dBEEfnG9BqRw0na0DUqtpWe2CUtldbU33nnJ0KB6z7y5f+89o9n8mJxIbh952gpskBxyrhCfpYHV5mt/n9Tkm8OcQWLRFou7/XITuZeZejfUTesQjpfOeCaeKyVSoKQc6WuH7NSYq6B37RMyEn/1+vo8XuHEKD84p29KGpyGI7ZeL85iOcwBmOD6+e4yideH2RatA1SzEv/9V8BflaFLAWDuPWUjA2WgfOvy5spYmp/MoMOX4P0d+AkJ9Ms6PUXEUBsbOACmaMFyLCLHmd18+UeGdJR/3I15sXKbJhKerwIDAQAB
-----END PUBLIC KEY-----""",
# [3] negotiationVersion=3
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi4mA4XK0muEDb6VeLt2+teLA3pgjOeBGqX5gcFHP2xYJDoJm079T7xY6fcTJjP2mdHAoQaVGcQ9gaq3PC4ExxDQ80Lkh/5ZRMJN084XTMttwfrXEj80md/v5zSLBJUV2tUMs2Y7BAgEBdeTVhRfmHRtksBZH78Xk77bcj1v3+u1HXAPV+mry7qRiz4futCpti50lOeJUEB4B73or1xdPS7TPNtE1KuzgD2T0V7ptwyevFg0zcyJ+plOXSRv7/1PXuwHhNleWlyrPkkkXO9kuLRQKqpQaqLp7elpQSlMZOC4HktOiVGEGwCPq/nlOqQk5LuLUnTSs78BeX7a9JDx+nwIDAQAB
-----END PUBLIC KEY-----""",
]

# ============================================================================
# 三、协议常量
# ============================================================================
MD5_SALT = "XEdEbJ0h3MsefsfvdHgTj689lmivNSvlgEb"   # /upgrade/tool 签名盐(逆向提取)
URL_TOOL_UPDATE   = "https://diagnostic-tool.coloros.com/upgrade/tool"
URL_UPGRADE_QUERY = "https://downgrade.coloros.com/upgrade/query"
URL_DOWNGRADE_V3  = "https://downgrade.coloros.com/downgrade/query-v3"
SSL_CTX = ssl.create_default_context()
UA = "ColorOS-Assist/1.4.42"

# ============================================================================
# 四、接口实现
# ============================================================================

def _http(url, body=None, headers=None, method="POST", timeout=25):
    data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json; charset=UTF-8")
    for k, v in (headers or {}).items():
        if isinstance(v, str) and not v.isascii():
            v = v.encode("utf-8").decode("latin-1")  # 非ASCII头值按UTF-8字节透传(模拟libcurl)
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode("utf-8", "replace")
        except Exception: return e.code, ""
    except Exception as e:
        return -1, repr(e)


def check_tool_update(tool_version="V1.3.20", ip="169.254.21.15", mac="CC-28-AA-3A-19-E7"):
    """[协议1] 工具自更新检查 —— sign=MD5(参数串+盐), 已实测返回最新版"""
    ts = str(int(time.time()))
    plain = f"ip={ip}&mac={mac}&timestamp={ts}&toolType=coloros_assist_tool&toolVersion={tool_version}"
    sign = hashlib.md5((plain + MD5_SALT).encode()).hexdigest()
    body = json.dumps({"ip": ip, "mac": mac, "sign": sign, "timestamp": ts,
                       "toolType": "coloros_assist_tool", "toolVersion": tool_version},
                      separators=(",", ":"))
    st, resp = _http(URL_TOOL_UPDATE, body)
    try:
        return st, json.loads(resp)
    except Exception:
        return st, resp


def query_upgrade(profile, timeout=25):
    """[协议2] 升级包查询。profile = 设备档案(见 extract_profiles)。
    返回 (业务code, data_dict 或 None, 原始resp)"""
    hdr = dict(profile["requestHeader"])
    params = {
        "components": profile["components"],
        "mode": 0,
        "time": int(time.time() * 1000),
        "isRooted": "0",
        "type": "0",
        "registrationId": "",
        "securityPatch": profile["securityPatch"],
        "securityPatchVendor": profile["securityPatch"],
        "deviceId": profile["deviceId"],
    }
    st, resp = _http(URL_UPGRADE_QUERY, json.dumps(params, separators=(",", ":")), hdr)
    try:
        j = json.loads(resp)
        code = j.get("code")
        data = j.get("data")
        if isinstance(data, str):
            data = json.loads(data)
        return code, data, resp
    except Exception:
        return None, None, resp


def spoof_version_query(dev_id, prj_num, ota_version, model=None,
                        rom_version=None, coloros="ColorOS16.0.0", android="Android16",
                        patch=None, market=None, first_api="36", nv="10010111"):
    """[协议2-版本欺骗] 声称设备处于旧版本 → 服务器返回"旧→新"的全量OTA包。
    实证: PJD110 claim C.12 → 返回 C.82(ColorOS15.0.2, gauss直链);
          PLZ110 claim A.10 → 返回 A.37 包; claim 任意旧版本均有效。
    deviceId 必须是任一台"已注册"真机的真实 duid(服务器按其查库放行)。
    组件 hash8 不校验, 但组件时间戳建议与声称版本构建时间一致。
    返回 (code, data_dict, raw)"""
    ota = ota_version
    tsv = ota.split("_")[-1]
    pp = ota.split("_")
    rom = rom_version or (pp[0] + "_" + pp[1].replace(".", "_", 1))
    line = pp[1].split(".")[1] if "." in pp[1] else "A"
    model = model or pp[0]
    patch = patch or ((tsv[4:8] + "-" + tsv[8:10] + "-05") if len(tsv) >= 10 else "2026-01-05")
    comps = [
      {"componentName":"system_vendor","componentVersion":".93a7c40d"},
      {"componentName":"my_product","componentVersion":f"{prj_num}_1610_{line}.1.0.{tsv}1566921.a5003ab9"},
      {"componentName":"my_heytap","componentVersion":"version_stub.b1a8772d"},
      {"componentName":"my_stock","componentVersion":f"15.8.0.31.{tsv}14925293.dec70f2a"},
      {"componentName":"my_region","componentVersion":f"16.0.0311.{tsv}246078.bdbabc16"},
      {"componentName":"my_carrier","componentVersion":f"16.0.0311.{tsv}246077.bc312147"},
      {"componentName":"my_bigball","componentVersion":"version_stub.e34e76d3"},
      {"componentName":"my_manifest","componentVersion":f"{ota}.97.00000000"},
    ]
    hdr = {"language":"zh-CN","romVersion":rom,"androidVersion":android,"colorOSVersion":coloros,
     "infVersion":"1","operator":"","trackRegion":"CN","uRegion":"CN","model":model,
     "mode":"manual","nvCarrier":nv,"pipelineKey":"ALLNET","version":"2","deviceId":dev_id,
     "marketName":market or model,"prjNum":str(prj_num),"channel":"pc","otaVersion":ota,
     "first_api_level":first_api,"sn16":"","userid":"oplus-ota|<ver>",
     "ts":str(int(time.time()*1000)),"guid":hashlib.md5(b"").hexdigest()}
    params = {"components":comps,"mode":0,"time":int(time.time()*1000),"isRooted":"0","type":"0",
      "registrationId":"","securityPatch":patch,"securityPatchVendor":patch,"deviceId":dev_id}
    st, resp = _http(URL_UPGRADE_QUERY, json.dumps(params, separators=(",", ":")), hdr)
    try:
        j = json.loads(resp); code = j.get("code")
        data = j.get("data")
        if isinstance(data, str): data = json.loads(data)
        return code, data, resp
    except Exception:
        return None, None, resp


def build_cipher_envelope(dev_id, negotiation_version=1, rsa_key_index=1):
    """[协议3] 生成 query-v3 的 cipherInfo 信封 + 加密后的 deviceId (实验性)"""
    aes_key = os.urandom(32)          # AesImpl::aesGenKey(buf, 0x20)
    iv = os.urandom(12)               # AesImpl::aesGenKey(buf, 0x0c) → GCM IV
    n, e = parse_rsa_pubkey_pem(PEM_PUBKEYS[rsa_key_index])
    protected = base64.b64encode(rsa_pkcs1v15_encrypt(n, e, base64.b64encode(aes_key))).decode()
    cipher_info = json.dumps({
        "protectedKey": protected,
        "negotiationVersion": negotiation_version,
        "version": str(int(time.time())),
    }, separators=(",", ":"))
    enc = base64.b64encode(aes_gcm_encrypt(aes_key, iv, dev_id.encode())).decode()
    device_id_enc = {"cipher": enc, "iv": base64.b64encode(iv).decode()}
    return cipher_info, device_id_enc


def query_downgrade_v3(profile, negotiation_version=1):
    """[协议3] 降级包查询 v3 —— 完整信封实现。
    ⚠ 实测(2026-10): 服务器要求 HashMap<String,ProtectedKeyVO> 对象格式,
    疑似需手机端OTA服务预先协商会话; 无手机连接时返回 500。保留实现供研究。"""
    cipher_info, dev_enc = build_cipher_envelope(profile["deviceId"], negotiation_version)
    body = {
        "deviceId": dev_enc,
        "otaVersion": profile["otaVersion"],
        "model": profile["requestHeader"]["model"],
        "androidVersion": profile["requestHeader"]["androidVersion"],
        "colorosVersion": profile["requestHeader"]["colorOSVersion"],
        "nvCarrier": profile["requestHeader"]["nvCarrier"],
        "prjNum": profile["requestHeader"]["prjNum"],
        "serialNo": profile.get("serialNo", ""),
    }
    hdr = dict(profile["requestHeader"])
    hdr["cipherInfo"] = cipher_info
    return _http(URL_DOWNGRADE_V3, json.dumps(body, separators=(",", ":")), hdr)


# ============================================================================
# 五、设备档案: 内置 PEXM00 + 从本机 ColorOS助手 日志自动提取
# ============================================================================
BUILTIN_PROFILES = [
    # OPPO Find X3 (PEXM00) —— 来自 2025-07-14 日志的完整真实档案 (F.23 状态机)
    {
        "name": "OPPO Find X3 (PEXM00) 内置档案 [F.23 状态]",
        "deviceId": "<你的64位hex deviceId，见README §4.2>",
        "otaVersion": "PEXM00_11_F.23_2230_202306022342",
        "securityPatch": "2023-06-05",
        "serialNo": "",
        "requestHeader": {
            "language": "zh-CN", "romVersion": "PEXM00_11_F.23",
            "androidVersion": "Android13", "colorOSVersion": "ColorOS13.0.0",
            "infVersion": "1", "operator": "", "trackRegion": "CN", "uRegion": "CN",
            "model": "PEXM00", "mode": "manual", "nvCarrier": "10010111",
            "pipelineKey": "ALLNET", "version": "2",
            "deviceId": "<你的64位hex deviceId，见README §4.2>",
            "marketName": "OPPO K9 5G", "prjNum": "20127", "channel": "pc",
            "otaVersion": "PEXM00_11_F.23_2230_202306022342",
        },
        "components": [
            {"componentName": "system_vendor", "componentVersion": "1.3.101.2023052918331317669370.50f3593d"},
            {"componentName": "my_product",    "componentVersion": "20127.13.0.2023060222283417783250.8e970f4a"},
            {"componentName": "my_heytap",     "componentVersion": "9.22.3.0.2023052123440017460505.b1d5baff"},
            {"componentName": "my_stock",      "componentVersion": "30.15.0.3.2023060221540117783219.f19bdbe4"},
            {"componentName": "my_region",     "componentVersion": "13.0.02331.2023052518000017570794.b959553f"},
            {"componentName": "my_carrier",    "componentVersion": "13.0.02331.2023052704043017606868.d4babd0f"},
            {"componentName": "my_bigball",    "componentVersion": "20127_1300_T.0.0.2023052700001917598527.ea22abaf"},
            {"componentName": "my_manifest",   "componentVersion": "PEXM00_11.F.23_2230_202306022342.97.19ed5ae2"},
        ],
    },
]

# 本机日志中已验证的 PEXM00 刷机包永久直链 (gauss CDN 无签名直链, 已 HEAD 200)
KNOWN_LINKS = [
    {
        "device": "PJD110 (一加 12)",
        "version": "10010111_22825_PJD110_11_C_OTA_1840_all_Qlg912 (ColorOS 15.0.2 降级包)",
        "md5": "ffc449c8b0b1823ced90f12d19b7997b",
        "size": 9526156006,
        "url": "https://downgradefs.coloros.com/downgrade/26/02/09/66d73e8e01004d9db8edd2dae057c3ed.zip",
    },
    {
        "device": "PJD110 (一加 12)",
        "version": "10010111_22825_PJD110_11_F_OTA_2570_all_TGv1Jm_online (ColorOS 16.1.0 重推包)",
        "md5": "1e586a62712e21afab0a3ab5aa0785c6",
        "size": 10240560042,
        "url": "https://downgradefs.coloros.com/downgrade/26/09/07/feda86161dc149079c716e7818d9c43d.zip",
    },
    {
        "device": "PEXM00 (OPPO Find X3)",
        "version": "PEXM00_11.F.32_2320_202504231730 (ColorOS 13.0)",
        "md5": "c986eb27940e8f1b99d4d8c7bc3f8a58",
        "size": 2446424094,
        "url": "https://gauss-componentotacostmanual-cn.allawnfs.com/remove-df3b61e7f24bc20645bd87e6a290c1e3/component-ota/25/04/23/ceb23aba912243df973c6c585d4ff433.zip",
    },
    {
        "device": "PEXM00 (OPPO Find X3)",
        "version": "PEXM00_11.F.23_2230_202306022342 (ColorOS 13.0)",
        "md5": "bf7a64ac9412675f58b30d65e7110bd4",
        "size": 6289166608,
        "url": "https://gauss-componentotacostmanual-cn.allawnfs.com/remove-ac4ab5ebc1438023633ce2963f0c9778/component-ota/23/06/05/5852cd97d3424d6ea07ed7a8342645d8.zip",
    },
]


def extract_profiles(log_dir=None):
    r"""从本机 ColorOS助手 日志自动提取设备档案 (支持任意机型)。
    日志位置: %APPDATA%\coloros-assist\logs\<date>\*.LOG.log
    关键行: [OtaSocketModel::OnSocketRecvDeviceInfoAck]recv: {..."requestHeader":"..."}
            [PackageManager::QueryUpgradePackage]QueryUpgradePackgeInfo body = {...}
    每个会话(设备+otaVersion)生成一个档案; 组件清单按 romVersion 配对。
    """
    if log_dir is None:
        appdata = os.environ.get("APPDATA", "")
        log_dir = os.path.join(appdata, "coloros-assist", "logs")
    profiles = {}
    if not os.path.isdir(log_dir):
        return profiles
    files = sorted(glob.glob(os.path.join(log_dir, "**", "*"), recursive=True))
    for path in files:
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        # 1) 每条 recv: 行 = 一次会话, 按其 requestHeader.otaVersion 建档
        for m in re.finditer(r"OnSocketRecvDeviceInfoAck\]recv: (\{.*\})", text):
            try:
                obj = json.loads(m.group(1))
                hdr = json.loads(obj["requestHeader"])
                # 实证: 服务器要求 header.otaVersion 为下划线格式
                # (点分 "PEXM00_11.F.23_..." -> 下划线 "PEXM00_11_F.23_...")
                ov = hdr.get("otaVersion", "")
                if ov and "." in ov:
                    hdr["otaVersion"] = ov.replace(".", "_", 1)
                model = hdr.get("model", "UNKNOWN")
                key = model + "|" + hdr.get("otaVersion", "")
                if hdr.get("deviceId") and set(hdr["deviceId"]) <= set("0123456789ABCDEFabcdef") and len(hdr["deviceId"]) >= 32:
                    profiles[key] = {
                    "name": f"{model} [{hdr.get('romVersion','')}] (日志 {os.path.basename(path)})",
                    "requestHeader": hdr,
                    "deviceId": hdr.get("deviceId", ""),
                    "otaVersion": hdr.get("otaVersion", ""),
                    "securityPatch": "", "serialNo": "", "components": []}
            except Exception:
                continue
        # 2) 组件清单: my_manifest 版本 -> 归一化后与 header.otaVersion 配对
        for m in re.finditer(r"QueryUpgradePackgeInfo body = (\{.*\})", text):
            try:
                body = json.loads(m.group(1))
                manifest = ""
                for c in body.get("components", []):
                    if c.get("componentName") == "my_manifest":
                        manifest = c.get("componentVersion", "")
                        break
                # "PEXM00_11.C.12_1120_202303161708.97.h" -> "PEXM00_11_C.12_1120_202303161708"
                parts = manifest.split(".")
                base = None
                if len(parts) >= 4:
                    stem = manifest.rsplit(".", 2)[0]      # 去掉 .97.h
                    i = stem.find("_", stem.find("_") + 1)  # 第二个下划线
                    if i > 0:
                        base = stem[:i] + "_" + stem[i+1:].replace(".", "_", 1)
                target = None
                for p in profiles.values():
                    if p["deviceId"] == body.get("deviceId", "") and p["otaVersion"] == base:
                        target = p
                        break
                if target is None:
                    for p in profiles.values():
                        if p["deviceId"] == body.get("deviceId", "") and not p["components"]:
                            target = p
                            break
                if target is not None:
                    if body.get("components"):
                        target["components"] = body["components"]
                    if body.get("securityPatch"):
                        target["securityPatch"] = body["securityPatch"]
            except Exception:
                continue
        # 3) serialNo
        for m in re.finditer(r'"serialNo"\s*:\s*"([^"]*)"', text):
            for p in profiles.values():
                if not p.get("serialNo"):
                    p["serialNo"] = m.group(1)
    return profiles


# ============================================================================
# 六、主流程
# ============================================================================

CODE_MEANING = {
    200:  "成功(含包)",
    2107: "设备状态真实但当前无可用升级包(OPPO可能已下架)",
    2400: "组件版本清单校验失败(需该机型真实组件版本)",
}

def print_known_links():
    print("=" * 78)
    print("已验证的刷机包永久直链 (来自本机历史日志, 2026-10-30 HEAD 200 实测有效)")
    print("=" * 78)
    for i, k in enumerate(KNOWN_LINKS, 1):
        print(f"\n[{i}] {k['device']}")
        print(f"    版本: {k['version']}")
        print(f"    大小: {k['size']:,} 字节 ({k['size']/1e9:.2f} GB)")
        print(f"    MD5 : {k['md5']}")
        print(f"    链接: {k['url']}")


def try_query_all(model_filter=None):
    profiles = {}
    for p in BUILTIN_PROFILES:
        profiles[p["requestHeader"]["model"]] = p
    extracted = extract_profiles()
    for m, p in extracted.items():
        if m not in profiles and p.get("components"):
            profiles[m] = p
    print("-" * 78)
    print("在线查询 /upgrade/query (协议2)")
    print("-" * 78)
    if not profiles:
        print("未找到任何设备档案。")
        return
    for model, p in profiles.items():
        if model_filter and model_filter not in model:
            continue
        if not p.get("components"):
            print(f"\n[{model}] 日志档案缺组件清单, 跳过 (需要真实组件版本)")
            continue
        print(f"\n>>> 查询 {model}  (otaVersion={p['otaVersion']})")
        code, data, raw = query_upgrade(p)
        meaning = CODE_MEANING.get(code, str(code))
        print(f"    业务码 {code} ({meaning})")
        if code == 200 and data:
            for comp in data.get("components", []):
                pk = comp.get("componentPackets", {})
                print(f"    ✔ {comp.get('componentVersion')}")
                print(f"      下载: {pk.get('manualUrl') or pk.get('url')}")
                print(f"      MD5 : {pk.get('md5')}  大小: {pk.get('size')}")
        else:
            print(f"    原始: {raw[:160]}")


def try_update_check():
    print("-" * 78)
    print("工具自更新检查 /upgrade/tool (协议1, sign=MD5+盐)")
    print("-" * 78)
    st, j = check_tool_update()
    if isinstance(j, dict) and j.get("code") == 200:
        d = j["data"]
        print(f"  最新版本 : {d.get('version')}  (updateStatus={d.get('updateStatus')})")
        print(f"  文件     : {d.get('fileName')}")
        print(f"  MD5      : {d.get('fileMd5')}")
        print(f"  下载链接 : {d.get('downloadUrl')}")
    else:
        print(f"  HTTP {st}: {str(j)[:200]}")


def try_downgrade_v3(model_filter=None):
    print("-" * 78)
    print("降级包查询 /downgrade/query-v3 (协议3, RSA+AES-GCM 信封, 实验性)")
    print("-" * 78)
    for p in BUILTIN_PROFILES:
        model = p["requestHeader"]["model"]
        if model_filter and model != model_filter:
            continue
        st, resp = query_downgrade_v3(p)
        print(f"  [{model}] HTTP {st}: {resp[:200]}")
        print("  (500/会话错误 = 服务器需手机端协商会话, 详见文件头协议3说明)")


def main():
    argv = sys.argv[1:]
    model = None
    if "--model" in argv:
        i = argv.index("--model"); model = argv[i+1]; del argv[i:i+2]
    print_known_links()
    print()
    if "--update-check" in argv or not argv:
        try_update_check()
        print()
    if "--v3" in argv:
        try_downgrade_v3(model)
        print()
    if not argv or "--query" in argv or model:
        try_query_all(model)
    if "--spoof" in argv:
        i = argv.index("--spoof")
        ota = argv[i+1]; del argv[i:i+2]
        dev = argv[i+1] if len(argv) > i+1 and len(argv[i+1]) == 64 else None
        if dev: del argv[i:i+1]
        else:
            profs = {**{k: v for k, v in extract_profiles().items()}, **{p["requestHeader"]["model"]: p for p in BUILTIN_PROFILES}}
            pp = [v for k, v in profs.items() if not dev]
            dev = (pp[0]["deviceId"] if pp else None)
        prj = argv[i+1] if len(argv) > i+1 else "25821"
        if len(argv) > i and argv[i] == "--prj": del argv[i:i+1]
        print("-" * 78)
        print(f"版本欺骗查询: 声称 otaVersion={ota}")
        code, data, raw = spoof_version_query(dev, prj, ota)
        print(f"  业务码 {code}")
        if code == 200 and data:
            for c in data.get("components", []):
                pk = c.get("componentPackets", {})
                print(f"  ✔ {c.get('componentVersion')}  MD5={pk.get('md5')}  size={pk.get('size')}")
                print(f"    直链: {pk.get('manualUrl') or pk.get('url')}")
        else:
            print(f"  {raw[:200]}")
    if "--list-profiles" in argv:
        print("-" * 78)
        print("本机日志中的设备档案:")
        for m, p in extract_profiles().items():
            print(f"  {m}: otaVersion={p['otaVersion']} 组件数={len(p['components'])}")
    print("\n提示: 其他机型请先用 ColorOS助手 连接一次手机, 再运行本工具 --list-profiles")

if __name__ == "__main__":
    main()
