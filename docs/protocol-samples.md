# 脱敏真实报文样本

> 以下样本均来自真实抓取，**个人标识已脱敏**（deviceId/serial/MAC/IP 以 `<REDACTED>` 或 `...` 表示）。

## 1. PC↔手机握手（cmdId 40001，OTA socket）

PC → 手机：
```json
{"cmdId":40001,"createTime":1752422803213002,"needAck":true,
 "uuid":"E6F66D46BEE04988B9BADCC552B7B2B9",
 "extraInfo":"{\"pubKey\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzrEEcAUww1W2kKVelw0Td5/2vReWgUKJGieMsDV/TxC5PwFsi1MgWSnlhcAN85mAdnLaHrS3aUHffA/2CwKzmQ==\",\"signData\":\"1752422803276JlmIaZbO60y+1ao01752422803211737\",\"signValue\":\"MEUCIBceoIk9Ae6X3q22AOZD07JOmcFNOYP4cfAQz+6yMaXkAiEArqgBP7gFgoVlC4cnyVLAb4E/02VJw4JWI4MhtgiBz1o=\",\"verifyPass\":true}"}
```

- `pubKey`：SPKI DER (P-256) base64
- `signData`：`<毫秒时间戳><16位随机串><微秒时间戳>`
- `signValue`：ECDSA-P256-SHA256(signData)，DER —— **已用 pubKey 验签通过**

## 2. 手机 → PC DeviceInfoAck（设备档案下发）

```json
{"upgradeRequestBody":"{\"params\":\"{\\\"components\\\":[...8组件...],\\\"mode\\\":0,...,\\\"deviceId\\\":\\\"<64hex>\\\"}\"}",
 "downgradeRequestBody":"{\"params\":\"{\\\"otaVersion\\\":\\\"...\\\",\\\"deviceId\\\":\\\"<64hex>\\\",...}\"}",
 "requestHeader":"{\"language\":\"zh-CN\",\"romVersion\":\"...\",\"androidVersion\":\"...\",\"colorOSVersion\":\"...\",\"infVersion\":\"1\",\"operator\":\"\",\"trackRegion\":\"CN\",\"uRegion\":\"CN\",\"model\":\"...\",\"mode\":\"manual\",\"nvCarrier\":\"10010111\",\"pipelineKey\":\"ALLNET\",\"version\":\"2\",\"deviceId\":\"<64hex>\",\"marketName\":\"...\",\"prjNum\":\"...\",\"channel\":\"pc\",\"otaVersion\":\"...\",\"first_api_level\":\"34\",\"sn16\":\"\",\"userid\":\"oplus-ota|16001015\",\"ts\":\"...\",\"guid\":\"d41d8cd98f00b204e9800998ecf8427e\"}"}
```

## 3. 降级查询 query-v3 成功报文（请求体，头略）

```json
{"androidVersion":"Android16","colorosVersion":"ColorOS16.1.0",
 "deviceId":{"cipher":"<b64, 64B明文+16B tag>","iv":"<b64, 12B>"},
 "model":"<model>","nvCarrier":"10010111",
 "otaVersion":"<model>_11.F.57_2570_202608111410",
 "prjNum":"22825","serialNo":"<serial>"}
```

响应（节选）：
```json
{"code":200,"data":{"metaData":"<b64 RSA签名>",
 "downgradeVoList":[{"downloadUrl":"https://downgradefs.coloros.com/downgrade/26/02/09/<md5>.zip",
   "otaVersion":"10010111_22825_PJD110_11_C_OTA_1840_all_Qlg912",
   "colorosVersion":"ColorOS15.0.2","androidVersion":"Android15",
   "fileSize":9526156006,"fileMd5":"ffc449c8b0b1823ced90f12d19b7997b"}]}}
```

## 4. 版本欺骗升级查询（声称 C.12 → 返回 C.82 全量包）

请求体（节选）：
```json
{"components":[{"componentName":"system_vendor","componentVersion":".93a7c40d"},
  {"componentName":"my_product","componentVersion":"22825_1610_A.1.0.2023031617081566921.a5003ab9"},
  {"componentName":"my_heytap","componentVersion":"version_stub.b1a8772d"},
  {"componentName":"my_stock","componentVersion":"15.8.0.31.20230316170814925293.dec70f2a"},
  {"componentName":"my_region","componentVersion":"16.0.0311.202303161708246078.bdbabc16"},
  {"componentName":"my_carrier","componentVersion":"16.0.0311.202303161708246077.bc312147"},
  {"componentName":"my_bigball","componentVersion":"version_stub.e34e76d3"},
  {"componentName":"my_manifest","componentVersion":"PJD110_11.C.12_1120_202303161708.97.00000000"}],
 "mode":0,"time":<毫秒>,"isRooted":"0","type":"0","registrationId":"",
 "securityPatch":"2023-03-05","securityPatchVendor":"2023-03-05","deviceId":"<64hex>"}
```

响应（节选，注意 **vabInfo 含完整刷机元数据**）：
```json
{"code":200,"data":"{\"components\":[{\"componentId\":\"my_manifest_PJD110_11.C.82_1820_202509031656.97.d9df0761\",
  \"componentPackets\":{\"size\":\"7860899281\",
  \"vabInfo\":{\"data\":{\"otaStreamingProperty\":\"payload_metadata.bin:2972:282578,payload.bin:2972:7860892627,...\",
    \"vab_package_hash\":\"bb3c50f36650178e9da4d35c1ae46f1b\",
    \"extra_params\":\"metadata_hash:02314ba2...\",\"header\":[\"FILE_HASH=...\",\"android_version=15\",
    \"forbid_ota_local_update=false\",\"ota_target_version=PJD110_11.C.82_1820_202509031656\",
    \"oplus_rom_version=V15.0.2\",\"security_patch=2025-09-01\",\"oplus_separate_soft=22825\"]}},
  \"manualUrl\":\"https://gauss-componentotacostmanual-cn.allawnfs.com/remove-8158f0d4dfbc2be0e4987529d23ff7cd/component-ota/25/09/04/780c853c34dc45c1818d3639e029ed1c.zip\",
  \"md5\":\"bb3c50f36650178e9da4d35c1ae46f1b\"}}]"}}
```

## 5. downloadCheck 签名下载（带设备头流式返回）

```
GET https://component-ota-cn.allawntech.com/downloadCheck?c=<32hex>&p=<126hex>&d=<126hex>&g=<32hex>&id=<16hex>&taste=0&supportDLTaste=0&mode=1&tr=manual&s=<32hex>
[需携带与查询相同的完整设备请求头]

无设备头 → {"body":null,"errMsg":"... 2306","responseCode":2306}
带头     → HTTP 206, Content-Range: bytes 0-2047/9170255308, application/zip
           前4字节 = PK\x03\x04 (ZIP, payload.bin 在列)
```

## 6. 自更新检查（sign 算法样本）

```
body = {"ip":"...","mac":"...","sign":"34ff1015ce14631504f9ace0de24a1ba","timestamp":"1752422786",
        "toolType":"coloros_assist_tool","toolVersion":"V1.3.20"}
sign = MD5("ip=<ip>&mac=<mac>&timestamp=1752422786&toolType=coloros_assist_tool&toolVersion=V1.3.20"
           + "XEdEbJ0h3MsefsfvdHgTj689lmivNSvlgEb")   ← 已验证命中
```
