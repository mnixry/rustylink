use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bitflags::bitflags;
use cbc::{
    Encryptor,
    cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7},
};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::HeaderMap;
use rustylink_proto::{buffa::Message, proto::rustylink::signing::v1::HttpSignHeader};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const AES_CBC_BLOCK_SIZE: usize = 16;
const DEFAULT_ROOT_KEY_VERSION: u64 = 1;
const FIXED_PASSWORD_KEY: &str = "8bfa9ad090fbbf87e518f1ce24a93eee";
const HTTP_SIGN_HKDF_SECRET: &[u8] = b"ygicehnydny4fj";

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SigningInputFlags: u64 {
        const METHOD = 1 << 1;
        const PATH = 1 << 2;
        const QUERY = 1 << 3;
        const BODY_SHA256 = 1 << 4;
        const COOKIE = 1 << 5;
        const ANDROID_RESERVED_6 = 1 << 6;
        const CSRF_TOKEN = 1 << 7;
        const KNOCK_TOKEN = 1 << 8;
        const JWT_TOKEN = 1 << 9;
        const _ = !0;
    }
}

#[derive(Clone, Debug, Default)]
pub struct SigningConfig {
    pub enabled: bool,
    pub root_key_version: u64,
    pub signing_input_params: u64,
    pub algorithms: Vec<String>,
    pub rules: Vec<SigningRuleConfig>,
    pub activation_code: Option<String>,
    pub device_id: Option<String>,
    pub hmac_key_base64: Option<String>,
    pub shared_secret: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SigningRuleConfig {
    pub urls: Vec<String>,
    pub enable_signing: bool,
    pub signing_input_params: u64,
    pub max_time_desync: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct SigningContext {
    config: SigningConfig,
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum SigningError {
    #[snafu(display("no signing secret configured"))]
    MissingSecret,

    #[snafu(display("invalid base64 signing key: {source}"))]
    InvalidBase64 { source: base64::DecodeError },

    #[snafu(display("invalid HMAC key: {source}"))]
    InvalidKey { source: hmac::digest::InvalidLength },
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
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
        if method.eq_ignore_ascii_case("PUT") || is_multipart(headers) {
            return Ok(Vec::new());
        }
        let Some(signing_input_flags) = self.signing_input_flags(url) else {
            return Ok(Vec::new());
        };
        let key = self.hmac_key()?;
        let input = signing_input(method, url, headers, body, signing_input_flags);
        let mut mac = HmacSha256::new_from_slice(&key).context(signing_error::InvalidKeySnafu)?;
        mac.update(&input);
        let signature = mac.finalize().into_bytes();
        let header =
            encode_http_sign_header(self.root_key_version(), signing_input_flags, &signature);
        Ok(vec![SignedHeader {
            name: "Sign".to_string(),
            value: format!("v1;{}", STANDARD.encode(header)),
        }])
    }

    fn hmac_key(&self) -> Result<Vec<u8>, SigningError> {
        if let Some(encoded) = self.config.hmac_key_base64.as_deref() {
            return STANDARD
                .decode(encoded)
                .context(signing_error::InvalidBase64Snafu);
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
            .context(signing_error::MissingSecretSnafu)
    }

    fn root_key_version(&self) -> u64 {
        if self.config.root_key_version == 0 {
            DEFAULT_ROOT_KEY_VERSION
        } else {
            self.config.root_key_version
        }
    }

    fn signing_input_flags(&self, url: &Url) -> Option<SigningInputFlags> {
        if self.config.rules.is_empty() {
            let flags = if self.config.signing_input_params == 0 {
                default_signing_input_flags()
            } else {
                SigningInputFlags::from_bits_retain(self.config.signing_input_params)
            };
            return Some(flags);
        }

        self.config
            .rules
            .iter()
            .find(|rule| {
                rule.enable_signing && rule.urls.iter().any(|candidate| candidate == url.path())
            })
            .map(|rule| {
                if rule.signing_input_params == 0 {
                    default_signing_input_flags()
                } else {
                    SigningInputFlags::from_bits_retain(rule.signing_input_params)
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
            return password_cipher_error::InvalidKeyLengthSnafu { length: key.len() }.fail();
        }
        let iv = aes_cbc_iv(&self.fixed_string);
        let mut buf = plaintext.as_bytes().to_vec();
        let plain_len = buf.len();
        buf.resize(plain_len + AES_CBC_BLOCK_SIZE, 0);
        let ciphertext = Encryptor::<Aes256>::new_from_slices(key, &iv)
            .map_err(|_| PasswordCipherError::InvalidKeyLength { length: key.len() })?
            .encrypt_padded::<Pkcs7>(&mut buf, plain_len)
            .map_err(|_| PasswordCipherError::Padding)?;
        Ok(hex::encode(ciphertext))
    }

    #[must_use]
    pub fn fixed_string(&self) -> &str {
        &self.fixed_string
    }
}

fn signing_input(
    method: &str, url: &Url, headers: &HeaderMap, body: &[u8],
    signing_input_flags: SigningInputFlags,
) -> Vec<u8> {
    let mut out = Vec::new();
    if signing_input_flags.contains(SigningInputFlags::METHOD) {
        out.extend_from_slice(method.as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::PATH) {
        out.extend_from_slice(url.path().as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::QUERY)
        && let Some(query) = url.query()
    {
        out.extend_from_slice(query.as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::BODY_SHA256) && !body.is_empty() {
        out.extend_from_slice(&Sha256::digest(body));
    }
    if signing_input_flags.contains(SigningInputFlags::COOKIE)
        && let Some(value) = header_value(headers, "cookie")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::CSRF_TOKEN)
        && let Some(value) = header_value(headers, "csrf-token")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::KNOCK_TOKEN)
        && let Some(value) = header_value(headers, "knock-token")
    {
        out.extend_from_slice(value.as_bytes());
    }
    if signing_input_flags.contains(SigningInputFlags::JWT_TOKEN)
        && let Some(value) = header_value(headers, "jwt-token")
    {
        out.extend_from_slice(value.trim().as_bytes());
    }
    out
}

fn default_signing_input_flags() -> SigningInputFlags {
    SigningInputFlags::METHOD
        | SigningInputFlags::PATH
        | SigningInputFlags::QUERY
        | SigningInputFlags::BODY_SHA256
        | SigningInputFlags::COOKIE
        | SigningInputFlags::ANDROID_RESERVED_6
        | SigningInputFlags::CSRF_TOKEN
        | SigningInputFlags::KNOCK_TOKEN
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

fn is_multipart(headers: &HeaderMap) -> bool {
    header_value(headers, "content-type")
        .is_some_and(|value| value.to_ascii_lowercase().starts_with("multipart/"))
}

fn aes_cbc_iv(key: &str) -> [u8; AES_CBC_BLOCK_SIZE] {
    // The IV is the first 16 bytes of the SHA-1 hex digest (always 40 chars, so
    // the zip fills the whole array).
    let digest_hex = hex::encode(Sha1::digest(key.as_bytes()));
    let mut iv = [0u8; AES_CBC_BLOCK_SIZE];
    for (slot, byte) in iv.iter_mut().zip(digest_hex.bytes()) {
        *slot = byte;
    }
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
    let mut extract = HmacSha256::new_from_slice(salt).context(signing_error::InvalidKeySnafu)?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut okm = Vec::with_capacity(length);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while okm.len() < length {
        let mut expand =
            HmacSha256::new_from_slice(&prk).context(signing_error::InvalidKeySnafu)?;
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
    root_key_version: u64, signing_input_flags: SigningInputFlags, signing_result: &[u8],
) -> Vec<u8> {
    HttpSignHeader {
        root_key_version,
        signing_input_params: signing_input_flags.bits(),
        signing_result: signing_result.to_vec(),
        ..HttpSignHeader::default()
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use reqwest::header::{HeaderMap, HeaderValue};
    use rustylink_proto::buffa::Message;
    use sha2::{Digest as _, Sha256};
    use url::Url;

    use super::{
        HttpSignHeader, PasswordCipher, SigningConfig, SigningContext, default_signing_input_flags,
        encode_http_sign_header, generate_http_sign_key_bytes,
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
        let signature = Sha256::digest(b"signing result").to_vec();
        let encoded = encode_http_sign_header(1, default_signing_input_flags(), &signature);
        let decoded = HttpSignHeader::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.root_key_version, 1);
        assert_eq!(
            decoded.signing_input_params,
            default_signing_input_flags().bits()
        );
        assert_eq!(decoded.signing_result, signature);
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
