# Static Evidence Notes

Source application:

- Android package: `com.volcengine.corplink`
- Version: `3.2.16`, version code `321600`
- First-party code package: `com.bytedance.topgo`
- VPN service: `com.bytedance.topgo.base.vpn.WgaVpnService`
- Native bridge class: `wireguard.Wireguard`

## Network Evidence

Primary decompile tree for this pass:

- `/tmp/rustylink-jadx-restart.Qq2w9V`, produced by `nix shell nixpkgs#jadx -c jadx ...`.

The normal HTTP interceptor adds:

- `Accept-Language`
- `User-Agent`
- cookie-backed `csrf-token` as a dedicated header
- optional `knock-token`

Common device query parameters are built from:

- `os`
- `os_version`
- `app_version`
- `brand`
- `model`
- `language`
- `build_number`
- `os_version_patch`
- server-adjusted `timestamp`
- `client_source=FeiLian`

Evidence:

- `defpackage/aa.java:15-22` appends `uu.B(...)` to every OkHttp request.
- `defpackage/uu.java:82-95` constructs the common query map.
- `defpackage/uu.java:262-276` URL-encodes that map for manual URL construction.
- `HttpsClientUtil.java:266-285` and `343-382` append the same query map for manual VPN GET/POST calls.

The device identifier from `uu.C(context)` is not sent as a common query field in this APK. It is used by HTTP signing key derivation, where `qd0.java:57-63` calls `Wireguard.generateHttpSignKey(jf.n("activate_code"), uu.C(...))`.

Endpoint server roles:

- FeiLian activation/discovery uses `POST /api/match` (`defpackage/s2.java:15`).
- Organization/tenant APIs use the selected tenant base URL, for example `/api/login`, `/api/info/me`, `/api/tenant/config`, `/api/setting`, and `/api/vpn/list` (`defpackage/s1.java`, `defpackage/va0.java`, `defpackage/vo0.java`).
- VPN control APIs use the selected VPN dot API host/port, not the tenant host. `VpnConfigModel.java:84-91` builds `VpnLocationBean.getApiUrl(apiIp, apiPort) + "/vpn/conn"`.
- The WireGuard endpoint uses the dot WireGuard host/port. `WgHelper.java:86-96` uses `currentDotBean.getApiIp()` and `currentDotBean.vpnPort`.

The VPN control endpoint is directly evidenced as:

- `POST /vpn/conn`
- `GET /vpn/ping`
- `GET /vpn/export`
- `POST /vpn/report`

Request body fields from `VpnConfigModel.request`:

- `mode`
- `public_key`
- `otp`
- `export_id`
- `sign_token`
- `not_auto`

Response fields parsed by the Android client:

- `data.ip`
- `data.ipv6`
- `data.ip_mask`
- `data.public_key`
- `data.preshared_key`
- `data.sign_token`
- `data.protocol_version`
- `data.setting.vpn_mtu`
- `data.setting.vpn_dns`
- `data.setting.vpn_dns_backup`
- `data.setting.vpn_dns_domain_split`
- `data.setting.vpn_route_full`
- `data.setting.vpn_route_split`
- `data.setting.v6_route_full`
- `data.setting.v6_route_split`
- `data.setting.vpn_dynamic_domain_route_split`
- `data.setting.v6_vpn_dynamic_domain_route_split`
- `data.setting.vpn_wildcard_dynamic_domain_route_split`
- `data.setting.suffix_wildcard_dynamic_domain_route_split`
- `data.setting.dynamic_domain`
- `data.setting.central_dns`
- `data.setting.ip_nats`

Retrofit route evidence has been extracted for implemented CLI endpoints:

- `defpackage/s2.java:15`: `POST /api/match`.
- `defpackage/s1.java:36-48`, `81-90`, `99`: legacy login, MFA, tenant, settings, VPN list, and security report routes.
- `defpackage/va0.java:37-64`, `71-77`: coroutine tenant/profile/settings/VPN and v2 OTP routes.
- `defpackage/vo0.java:18-54`: v1 login, OTP, MFA, radius, unit, countries, and login setting routes.
- `defpackage/gm1.java:17-29`: third-party login callback/link/token/device/FIDO authorize routes.
- `com/bytedance/topgo/passkey/api/PasskeyApi.java:20-44`: passkey/FIDO begin, finish, verify, list, update, delete routes.

Additional JADX evidence:

- `LoginV2ViewModel.loginByPwd` sends `login_scene`, `account_type`, `account`, and `password`; password is `Wireguard.encryptByAesCbc(Wireguard.generateFixedString(), password)`.
- `LoginV2ViewModel.sendCode` sends `login_scene`, `account_type`, `login_type`, and `account`.
- `LoginV2ViewModel.verifyCode` sends `login_scene`, `account_type`, `login_type`, `account`, and `code`.
- `vo0.m` is annotated `GET /api/login/setting`.
- `sr1.a` is annotated `GET @Url` and returns `VpnExportListInfoBean`.
- `TenantConfigBean.SigningConfig` contains `enable`, `algorithms`, `rules`, and `rulesMap`.
- `TenantConfigBean.SigningConfigRuler` contains `urls`, `enableSigning`, `signingInputParams`, and `maxTimeDesync`.
- `HttpSignHeaderBean.HttpSignHeader` protobuf fields include `root_key_version`, `signing_input_params`, `signing_key_salt`, and `signing_result`.
- Passkey Retrofit methods exist (`beginLogin`, `finishLogin`, registration, verify, credential list/update/delete), but passkey support is intentionally not implemented in the CLI scope.

## Native Evidence Targets

Primary IDA target:

- `lib/arm64-v8a/libgojni.so`
- extracted from `/Users/moonshot/Downloads/FeiLian_Android_arm_3.2.16_2008_d598be.apk`

Recovered native methods:

- `Java_wireguard_Wireguard_encryptByAesCbc` at `0x51eac8`
- `Java_wireguard_Wireguard_generateFixedString` at `0x51eb38`
- `Java_wireguard_Wireguard_generateHttpSignKey` at `0x51eb6c`
- Go implementations:
  - `wireguard.EncryptByAesCbc` at `0x511e90`
  - `wireguard.GenerateFixedString` at `0x511fe0`
  - `wireguard.aesCBCEncrypt` at `0x5120e0`
  - `wireguard.GenerateHttpSignKey` at `0x512520`

Recovered password encryption behavior:

- `GenerateFixedString` returns lowercase MD5 hex of decimal `0x1fffffffffffff`, i.e. `MD5("9007199254740991") = 8bfa9ad090fbbf87e518f1ce24a93eee`.
- `EncryptByAesCbc(key, plaintext)` uses `AES-256-CBC`.
- AES key bytes are the 32 ASCII bytes of the fixed string.
- IV is the first 16 ASCII bytes of lowercase hex `SHA1(key)`.
- Plaintext is PKCS#7 padded.
- Ciphertext is returned as lowercase hex, not base64.

Recovered HTTP signing behavior:

- `Wireguard.generateHttpSignKey(String, String)` trims and lowercases the first string, concatenates `lower(trim(first)) + "|" + second`, then runs HKDF-SHA256.
- HKDF input keying material is constant ASCII `ygicehnydny4fj`; salt is empty/nil; info is the concatenated string above; output length is 32 bytes and returned as standard base64.
- JADX `pd0.invoke` calls `Wireguard.generateHttpSignKey(jf.n("activate_code"), uu.C(TopGoApplication.f))`; the result is base64-decoded and used as the HMAC key.
- `jf.n("activate_code")` reads MMKV `Global` key `activate_code`.
- `uu.C(context)` is the Android device identifier used for signing key derivation; it is not one of the common query fields in this APK.
- JADX `qd0.intercept` creates the signing input by concatenating enabled fields from `signingInputParams`: bit 1 method, bit 2 encoded path, bit 3 encoded query, bit 4 SHA-256 request-body bytes, bit 5 `Cookie`, bit 7 `csrf-token`, bit 8 `knock-token`, bit 9 trimmed `jwt-token`.
- Default signing rule from `pd0.invoke` sets `enableSigning=true`, `signingInputParams=510`, and `maxTimeDesync=120`.
- Final `Sign` header is `v1;` plus standard base64 without wrapping of `HttpSignHeader` protobuf bytes.
- `HttpSignHeader` field numbers are `root_key_version=1`, `signing_key_salt=2`, `signing_input_params=3`, `signing_result=4`; Android sets root key version `1`, empty signing key salt, rule input params, and HMAC-SHA256 result bytes.

## VPN Behavior

Evidenced Android behavior:

- Connect attempts loop up to three times.
- Config fetch occurs before tunnel startup.
- `ServerOperator.java:31-111` chooses a dot, retries up to three dots, and retries config fetch up to three times for a dot.
- `ServerOperator.java:64-74` can use `vpnIp` for the config API when `ip_delay_routing_policy.isOperator && policyType == 1`; otherwise it uses `getApiIp()`.
- `VpnLocationBean.java:666-668` defines `getApiIp()` as `ip4Domain`, then `fastIp`, then `apiIp`.
- `VpnLocationBean.java:868-870` allows reconnect only when `reconnect && !dedicated && !exclude`.
- `LocalOperator.java:120-127` generates a local private/public key pair before config fetch; `LocalOperator.java:135-215` starts local UDP port selection at `12912`.
- `VpnConfigModel.java:66-74` sends `mode`, `public_key`, `otp`, `export_id`, `sign_token`, and `not_auto`.
- Tunnel startup configures TUN, then starts WireGuard, then checks `Wireguard.onTunOk`.
- `WgHelper.java:69-101` runs `tunnelInit`, `startup`, `configMode`, then `configSet`.
- `WgHelper.java:86-96` configures the peer endpoint from dot `getApiIp()` and `vpnPort`, keepalive `25`, dot `protocolMode`, protocol version, protocol detect flag, and device id.
- `WgHelper.java:18-56` passes DNS list, local DNS, dynamic split-domain JSON, central DNS JSON, IP NAT JSON, local address, export id, and user open id into `Wireguard.configMode`; the local DNS proxy port is `2913`.
- `VpnLocationBean.java:879-887` treats `protocolMode == 1 || protocolMode == 2` as TCP-capable and `protocolMode == 0 || protocolMode == 2` as UDP-capable.
- IDA `wireguardbase.(*nativeTCPBind).Send` at `0x4d4010` dials TCP and writes each WireGuard datagram as a 4-byte little-endian length followed by the payload.
- IDA `wireguardbase.(*nativeTCPBind).recvFromConn` at `0x4d4590` reads the same little-endian length prefix, rejects invalid frame lengths, then reads the framed payload.
- IDA `wireguardbase.init.0` at `0x4f9170` precomputes standard WireGuard Noise values and FeiLian `CorpLink v1 vpn@feilian-----------` values.
- IDA `wireguardbase.(*Device).CreateMessageInitiation` at `0x4f92f0` selects the CorpLink identifier only when `wgIdentifierVer` is exactly `v2`.
- IDA `wireguardbase.(*Device).DnsProxyStart` at `0x4dadb0`, `wireguardbase.newDnsMode` at `0x4e39c0`, and `wireguardbase.(*dnsmode).isInSplitDomainAndSend` at `0x4e6560` show a DNS proxy/filter path for UDP/53 split-domain handling rather than a config-only field.
- `VpnReportOperator.java:27-39` reports connect/disconnect to the dot API `/vpn/report` with `type`, `ip`, `public_key`, and `mode`.
- Handshake watcher polls every 500 ms.
- Handshake timeout depends on protocol mode: 15 s, 9 s, or 6 s.
- Server kick-out is reported as `vpn_server_kickout`.
- Reconnect coroutine is large and not fully decompiled by Jadx; Rust fallback uses bounded conservative backoff.

Rust implementation boundary:

- `crates/api/src/client.rs` injects the common query and signing headers while sending hand-written endpoint request structs, rather than declaring always-sent query parameters on every operation.
- `crates/core/src/vpn.rs` selects dots and requests `/vpn/conn` by sending the hand-written VPN request model with a per-dot client base URL override.
- `crates/tunnel/src/session.rs` uses `gotatun::device::DeviceBuilder`, `Peer`, and a `DnsHijackTun` wrapper to start a real WireGuard device.
- `protocol_mode=1` uses `crates/tunnel/src/transport.rs` FeiLian TCP framing over gotatun's custom UDP transport hook. `protocol_mode=0` and `protocol_mode=2` start UDP first, matching Android's UDP-capable condition.
- `protocol_version == "v2"` maps gotatun's `ProtocolIdentifier` to the recovered FeiLian CorpLink identifier; other protocol versions use standard WireGuard and log the evidence boundary.
- `crates/tunnel/src/dns.rs` starts a local UDP DNS proxy on FeiLian's port `2913` when DNS upstreams are configured and wraps TUN receive to intercept IPv4/IPv6 UDP destination port `53`, forward the DNS payload to selected local or VPN DNS upstreams, and synthesize the UDP response back to the TUN.
- Native protocol-detection switching thresholds and automatic UDP/TCP switching for `protocol_mode=2` are not fully reproduced yet; Rust starts with UDP for dual-capable dots.
