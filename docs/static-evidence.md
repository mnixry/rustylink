# Static Evidence Notes

Source application:

- Android package: `com.volcengine.corplink`
- Version: `3.2.16`, version code `321600`
- First-party code package: `com.bytedance.topgo`
- VPN service: `com.bytedance.topgo.base.vpn.WgaVpnService`
- Native bridge class: `wireguard.Wireguard`

## Network Evidence

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
- device identifier
- `build_number`
- `os_version_patch`
- server-adjusted `timestamp`
- `client_source=FeiLian`

The VPN control endpoint is directly evidenced as:

- `POST /vpn/conn`

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

Other API paths in `crates/api/spec/main.tsp` are named by feature and request/response model evidence. Their exact Retrofit route strings still need extraction from obfuscated interface annotations.

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
- `uu.C(context)` is the Android device identifier also used in common device query material.
- JADX `qd0.intercept` creates the signing input by concatenating enabled fields from `signingInputParams`: bit 1 method, bit 2 encoded path, bit 3 encoded query, bit 4 SHA-256 request-body bytes, bit 5 `Cookie`, bit 7 `csrf-token`, bit 8 `knock-token`, bit 9 trimmed `jwt-token`.
- Default signing rule from `pd0.invoke` sets `enableSigning=true`, `signingInputParams=510`, and `maxTimeDesync=120`.
- Final `Sign` header is `v1;` plus standard base64 without wrapping of `HttpSignHeader` protobuf bytes.
- `HttpSignHeader` field numbers are `root_key_version=1`, `signing_key_salt=2`, `signing_input_params=3`, `signing_result=4`; Android sets root key version `1`, empty signing key salt, rule input params, and HMAC-SHA256 result bytes.

## VPN Behavior

Evidenced Android behavior:

- Connect attempts loop up to three times.
- Config fetch occurs before tunnel startup.
- Tunnel startup configures TUN, then starts WireGuard, then checks `Wireguard.onTunOk`.
- Handshake watcher polls every 500 ms.
- Handshake timeout depends on protocol mode: 15 s, 9 s, or 6 s.
- Server kick-out is reported as `vpn_server_kickout`.
- Reconnect coroutine is large and not fully decompiled by Jadx; Rust fallback uses bounded conservative backoff.
