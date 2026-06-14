use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::{
    Encryptor,
    cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7},
};
use hmac::{Hmac, Mac};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_ROOT_KEY_VERSION: u64 = 1;
const DEFAULT_SIGNING_INPUT_PARAMS: u64 = 510;
const FIXED_PASSWORD_KEY: &str = "8bfa9ad090fbbf87e518f1ce24a93eee";
const HTTP_SIGN_HKDF_SECRET: &[u8] = b"ygicehnydny4fj";

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SigningConfig {
    pub enabled: bool,
    #[serde(default)]
    pub root_key_version: u64,
    #[serde(default)]
    pub signing_input_params: u64,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub rules: Vec<SigningRuleConfig>,
    #[serde(default)]
    pub activation_code: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub hmac_key_base64: Option<String>,
    #[serde(default)]
    pub shared_secret: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SigningRuleConfig {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub enable_signing: bool,
    #[serde(default)]
    pub signing_input_params: u64,
    #[serde(default)]
    pub max_time_desync: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SigningContext {
    config: SigningConfig,
}

#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)))]
pub enum SigningError {
    #[snafu(display("no signing secret configured"))]
    MissingSecret,

    #[snafu(display("invalid base64 signing key"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("invalid HMAC key"))]
    InvalidKey { source: hmac::digest::InvalidLength },
}

#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)))]
pub enum PasswordCipherError {
    #[snafu(display("AES-CBC padding failed"))]
    Padding,

    #[snafu(display("invalid AES key length {}; expected 32 bytes", length))]
    InvalidKeyLength { length: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct PasswordCipher {
    fixed_string: String,
}

impl SigningContext {
    #[must_use]
    pub fn new(config: SigningConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self::new(SigningConfig::default())
    }

    pub fn sign(
        &self, method: &str, url: &Url, headers: &HeaderMap, body: &[u8],
    ) -> Result<Vec<SignedHeader>, SigningError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }
        let Some(signing_input_params) = self.signing_input_params(url) else {
            return Ok(Vec::new());
        };
        let key = self.hmac_key()?;
        let input = signing_input(method, url, headers, body, signing_input_params);
        let mut mac = HmacSha256::new_from_slice(&key).context(signing_error::InvalidKey)?;
        mac.update(&input);
        let signature = mac.finalize().into_bytes();
        let header =
            encode_http_sign_header(self.root_key_version(), signing_input_params, &signature);
        Ok(vec![SignedHeader {
            name: "Sign".to_string(),
            value: format!("v1;{}", STANDARD.encode(header)),
        }])
    }

    fn hmac_key(&self) -> Result<Vec<u8>, SigningError> {
        if let Some(encoded) = self.config.hmac_key_base64.as_deref() {
            return STANDARD
                .decode(encoded)
                .context(signing_error::InvalidBase64);
        }

        if let (Some(activation_code), Some(device_id)) = (
            self.config.activation_code.as_deref(),
            self.config.device_id.as_deref(),
        ) {
            return generate_http_sign_key_bytes(activation_code, device_id);
        }

        self.config
            .shared_secret
            .as_ref()
            .map(|value| value.as_bytes().to_vec())
            .context(signing_error::MissingSecret)
    }

    fn root_key_version(&self) -> u64 {
        if self.config.root_key_version == 0 {
            DEFAULT_ROOT_KEY_VERSION
        } else {
            self.config.root_key_version
        }
    }

    fn signing_input_params(&self, url: &Url) -> Option<u64> {
        if self.config.rules.is_empty() {
            return Some(if self.config.signing_input_params == 0 {
                DEFAULT_SIGNING_INPUT_PARAMS
            } else {
                self.config.signing_input_params
            });
        }

        self.config
            .rules
            .iter()
            .find(|rule| {
                rule.enable_signing && rule.urls.iter().any(|candidate| candidate == url.path())
            })
            .map(|rule| {
                if rule.signing_input_params == 0 {
                    DEFAULT_SIGNING_INPUT_PARAMS
                } else {
                    rule.signing_input_params
                }
            })
    }
}

impl PasswordCipher {
    #[must_use]
    pub fn new(fixed_string: String) -> Self {
        Self { fixed_string }
    }

    #[must_use]
    pub fn generated() -> Self {
        Self::new(FIXED_PASSWORD_KEY.to_string())
    }

    pub fn encrypt_aes_cbc(&self, plaintext: &str) -> Result<String, PasswordCipherError> {
        let key = self.fixed_string.as_bytes();
        if key.len() != 32 {
            return password_cipher_error::InvalidKeyLength { length: key.len() }.fail();
        }
        let iv = aes_cbc_iv(&self.fixed_string);
        let mut buf = plaintext.as_bytes().to_vec();
        let plain_len = buf.len();
        buf.resize(plain_len + 16, 0);
        let ciphertext = Encryptor::<Aes256>::new_from_slices(key, &iv)
            .map_err(|_| PasswordCipherError::InvalidKeyLength { length: key.len() })?
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plain_len)
            .map_err(|_| PasswordCipherError::Padding)?;
        Ok(hex::encode(ciphertext))
    }

    #[must_use]
    pub fn fixed_string(&self) -> &str {
        &self.fixed_string
    }
}

fn signing_input(
    method: &str, url: &Url, headers: &HeaderMap, body: &[u8], signing_input_params: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    if bit_set(signing_input_params, 1) {
        out.extend_from_slice(method.as_bytes());
    }
    if bit_set(signing_input_params, 2) {
        out.extend_from_slice(url.path().as_bytes());
    }
    if bit_set(signing_input_params, 3)
        && let Some(query) = url.query()
    {
        out.extend_from_slice(query.as_bytes());
    }
    if bit_set(signing_input_params, 4) && !body.is_empty() {
        out.extend_from_slice(&Sha256::digest(body));
    }
    if bit_set(signing_input_params, 5)
        && let Some(value) = header_value(headers, "cookie")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if bit_set(signing_input_params, 7)
        && let Some(value) = header_value(headers, "csrf-token")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if bit_set(signing_input_params, 8)
        && let Some(value) = header_value(headers, "knock-token")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if bit_set(signing_input_params, 9)
        && let Some(value) = header_value(headers, "jwt-token")
    {
        out.extend_from_slice(value.trim().as_bytes());
    }
    out
}

fn bit_set(value: u64, bit: u8) -> bool {
    value & (1_u64 << bit) != 0
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn aes_cbc_iv(key: &str) -> [u8; 16] {
    let digest = Sha1::digest(key.as_bytes());
    let digest_hex = hex::encode(digest);
    let mut iv = [0_u8; 16];
    iv.copy_from_slice(&digest_hex.as_bytes()[..16]);
    iv
}

fn generate_http_sign_key_bytes(
    activation_code: &str, device_id: &str,
) -> Result<Vec<u8>, SigningError> {
    let normalized_code = activation_code.trim().to_ascii_lowercase();
    let info = format!("{normalized_code}|{device_id}");
    hkdf_sha256(HTTP_SIGN_HKDF_SECRET, &[], info.as_bytes(), 32)
}

fn hkdf_sha256(
    ikm: &[u8], salt: &[u8], info: &[u8], length: usize,
) -> Result<Vec<u8>, SigningError> {
    let mut extract = HmacSha256::new_from_slice(salt).context(signing_error::InvalidKey)?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut okm = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while okm.len() < length {
        let mut expand = HmacSha256::new_from_slice(&prk).context(signing_error::InvalidKey)?;
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(length);
    Ok(okm)
}

fn encode_http_sign_header(
    root_key_version: u64, signing_input_params: u64, signing_result: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    if root_key_version != 0 {
        encode_varint_field(1, root_key_version, &mut out);
    }
    if signing_input_params != 0 {
        encode_varint_field(3, signing_input_params, &mut out);
    }
    if !signing_result.is_empty() {
        encode_bytes_field(4, signing_result, &mut out);
    }
    out
}

fn encode_varint_field(field: u8, value: u64, out: &mut Vec<u8>) {
    encode_varint(u64::from(field) << 3, out);
    encode_varint(value, out);
}

fn encode_bytes_field(field: u8, value: &[u8], out: &mut Vec<u8>) {
    encode_varint((u64::from(field) << 3) | 2, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        let byte = u8::try_from(value & 0x7F).expect("varint byte is masked to 7 bits");
        out.push(byte | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("final varint byte is below 128"));
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use reqwest::header::{HeaderMap, HeaderValue};
    use url::Url;

    use super::{
        PasswordCipher, SigningConfig, SigningContext, encode_http_sign_header,
        generate_http_sign_key_bytes,
    };

    #[test]
    fn generated_password_cipher_uses_native_fixed_string() {
        let cipher = PasswordCipher::generated();
        assert_eq!(cipher.fixed_string(), "8bfa9ad090fbbf87e518f1ce24a93eee");
        let first = cipher.encrypt_aes_cbc("secret").expect("encrypt");
        let second = cipher.encrypt_aes_cbc("secret").expect("encrypt");
        assert_eq!(first, second);
        assert_eq!(first.len() % 32, 0);
    }

    #[test]
    fn http_sign_key_matches_native_shape() {
        let key = generate_http_sign_key_bytes("  TenantA  ", "device-1").expect("key");
        assert_eq!(key.len(), 32);
        assert_eq!(STANDARD.encode(key).len(), 44);
    }

    #[test]
    fn http_sign_header_uses_evidenced_proto_fields() {
        let encoded = encode_http_sign_header(1, 510, &[0xAB; 32]);
        assert_eq!(&encoded[..5], &[0x08, 0x01, 0x18, 0xFE, 0x03]);
        assert_eq!(encoded[5], 0x22);
        assert_eq!(encoded[6], 32);
        assert_eq!(encoded.len(), 39);
    }

    #[test]
    fn signing_header_is_android_sign_header() {
        let signer = SigningContext::new(SigningConfig {
            enabled: true,
            activation_code: Some("tenant".to_string()),
            device_id: Some("device".to_string()),
            ..SigningConfig::default()
        });
        let url = Url::parse("https://example.test/vpn/conn?client_source=FeiLian").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("csrf-token", HeaderValue::from_static("csrf"));
        let signed_headers = signer
            .sign("POST", &url, &headers, br#"{"a":1}"#)
            .expect("sign");
        assert_eq!(signed_headers.len(), 1);
        assert_eq!(signed_headers[0].name, "Sign");
        assert!(signed_headers[0].value.starts_with("v1;"));
    }
}
