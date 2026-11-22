# 秒秒测 MHO-H413 → ESP32-C5 → MQTT

单个 Cargo 包，无 workspace、vendor 或本地依赖补丁。硬件配置为 ESP32-C5、48 MHz 晶振、4 MB Flash，使用 esp-hal、esp-radio 和 esp-rtos。

## 网络与 TLS

- MQTT：`broker.emqx.io:8883`，TLS 1.3 加密的 TCP。
- Topic：`miaomiaoce/a4c1384d08a4/state`，QoS 0、不 retain。
- 原版 [embedded-tls](https://github.com/embassy-rs/embedded-tls/tree/6487c62bb084c33361822022e21836ddfd48388f)，固定上游提交 `6487c62`，直接使用它的 WebPKI CA 验证器。
- 密码算法使用原版 `embassy-crypto-rustcrypto`，固定提交 `822a76e`；随机数由 ESP32 硬件 TRNG 提供。
- 根 CA 为 `firmware/broker-ca.pem`，构建时转换为 DER 并编译进固件。校验证书链、域名、有效期和 TLS 握手签名，不固定服务器叶证书。

同一受信任根 CA 下正常换证不需要重新烧录；更换根 CA、采用不支持的算法或超出证书缓冲区上限时仍需调整固件。当前服务器叶证书缓冲区为 4096 字节。

连接前通过 SNTP 校时，要求从三个时间源中取得两个相差不超过 5 秒的样本；失败时不连接 TLS。时间源为 `time.cloudflare.com`、`ntp.aliyun.com`、`pool.ntp.org`。网络需允许 DNS、UDP 123 和 TCP 8883。SNTP 没有密码学认证，多源一致性检查不能防御同时篡改响应的攻击者。

MQTT 空闲 20 秒发送心跳，等待响应超过 15 秒重连；连接错误后等待 5 秒重试。数据变化最多每 2 秒发布一次，每 60 秒更新状态，断网期间不保存历史队列。

## 串口配网

使用开发板原生 USB Serial/JTAG 接口，终端可设为 115200、8N1，发送行尾选择 CRLF（\r\n）。固件串口消息也使用 CRLF。关闭串口工具本地回显；固件不回显输入。

1. 输入 `scan`，按信号从强到弱列出 Wi-Fi。
2. 输入列表编号。
3. 输入密码并回车，开放网络直接回车。
4. 连接成功后保存配置，重启自动连接。

支持开放网络及 WPA2-Personal；WPA3-only、企业认证等标记为 `Unsupported`。最多显示 24 个 AP，隐藏 SSID 不列出。密码中的空格保留。

- `scan`：重新扫描，旧编号失效。
- `status`：显示网络连接、数据、bindkey 是否设置及剩余堆。
- `key <32位十六进制>`：保存 bindkey。
- 输入密码时 `cancel`：取消选择。
- `help`：命令提示。

使用支持串口输入的终端工具，连接开发板对应的串口，关闭本地回显。

## 编译与烧录

在项目根目录执行：

```sh
rustup target add riscv32imac-unknown-none-elf
cargo build --features firmware --release --target riscv32imac-unknown-none-elf --locked
cargo run --features firmware --release --target riscv32imac-unknown-none-elf --locked
```

`cargo run` 通过 espflash 烧录，使用 `firmware/partitions.csv` 并自动识别 Flash 容量。晶振由 HAL 和 espflash 识别。设置区为 `0x1f0000..0x200000`，前两个 4 KB 扇区交替写入并做 CRC 校验；配置未加密。

Wi-Fi 凭据和设备 BLE bindkey 通过串口写入设置区。更换 bindkey 可直接再次执行 `key` 命令。

## 数据与目录

目标 MAC 为 `A4:C1:38:4D:08:A4`，产品 ID 为 `0x6bdf`。FE95 MiBeacon 使用 AES-128-CCM：MIC 4 字节，AAD=`0x11`，nonce=`MAC反序6B + 产品ID小端2B + 帧计数1B + 扩展计数3B`。

对象 `0x4c01` 为温度 f32 LE，`0x4c08` 为湿度 f32 LE，`0x4c1d` 推定为 CO₂ u16 LE，CO₂ 含义仍需与实物屏幕对照。JSON 包含温度、湿度、CO₂、各字段年龄、RSSI、帧计数和运行时间；未收到或超过 15 分钟未更新的字段为 `null`。

- `src/`：固件和内部模块。
- `firmware/`：分区表、CA 证书。
- `Cargo.lock`：原版依赖的锁定版本。

没有 ESP-IDF runtime 或 esp-idf-sys；`esp-bootloader-esp-idf` 仅提供标准镜像描述符，esp-radio 使用所需的 Espressif 无线库。项目不附带编译产物。
