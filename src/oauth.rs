use crate::{
	client::{CLIENT, OAUTH_CLIENT, OAUTH_IS_ROLLING_OVER, OAUTH_RATELIMIT_REMAINING},
	oauth_resources::ANDROID_APP_VERSION_LIST,
};
use arc_swap::ArcSwap;
use base64::{engine::general_purpose, Engine as _};
use futures_lite::future::block_on;
use log::{error, info, trace, warn};
use serde_json::json;
use std::{collections::HashMap, sync::atomic::Ordering, sync::LazyLock, time::Duration};
use tegen::tegen::TextGenerator;
use tokio::time::{error::Elapsed, timeout};

const REDDIT_ANDROID_OAUTH_CLIENT_ID: &str = "ohXpoqrZYub1kg";

const AUTH_ENDPOINT: &str = "https://www.reddit.com";

const OAUTH_TIMEOUT: Duration = Duration::from_secs(5);

// Response from OAuth backend authentication
#[derive(Debug, Clone)]
pub struct OauthResponse {
	pub token: String,
	pub expires_in: u64,
	pub additional_headers: HashMap<String, String>,
}

// Trait for OAuth backend implementations
trait OauthBackend: Send + Sync {
	fn authenticate(&mut self) -> impl std::future::Future<Output = Result<OauthResponse, AuthError>> + Send;
	fn user_agent(&self) -> &str;
	fn get_headers(&self) -> HashMap<String, String>;
}

// OAuth backend implementations
#[derive(Debug, Clone)]
pub(crate) enum OauthBackendImpl {
	MobileSpoof(MobileSpoofAuth),
	GenericWeb(GenericWebAuth),
	UserAuth(UserAuth),
	FixedToken(FixedTokenAuth),
}

impl OauthBackend for OauthBackendImpl {
	async fn authenticate(&mut self) -> Result<OauthResponse, AuthError> {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.authenticate().await,
			OauthBackendImpl::GenericWeb(backend) => backend.authenticate().await,
			OauthBackendImpl::UserAuth(backend) => backend.authenticate().await,
			OauthBackendImpl::FixedToken(backend) => backend.authenticate().await,
		}
	}

	fn user_agent(&self) -> &str {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.user_agent(),
			OauthBackendImpl::GenericWeb(backend) => backend.user_agent(),
			OauthBackendImpl::UserAuth(backend) => backend.user_agent(),
			OauthBackendImpl::FixedToken(backend) => backend.user_agent(),
		}
	}

	fn get_headers(&self) -> HashMap<String, String> {
		match self {
			OauthBackendImpl::MobileSpoof(backend) => backend.get_headers(),
			OauthBackendImpl::GenericWeb(backend) => backend.get_headers(),
			OauthBackendImpl::UserAuth(backend) => backend.get_headers(),
			OauthBackendImpl::FixedToken(backend) => backend.get_headers(),
		}
	}
}

// Spoofed client for Android devices
#[derive(Debug, Clone)]
pub struct Oauth {
	pub(crate) headers_map: HashMap<String, String>,
	expires_in: u64,
	pub(crate) backend: OauthBackendImpl,
}

impl Oauth {
	/// Create a new OAuth client
	pub(crate) async fn new() -> Self {
		use crate::config::get_setting;

		// Check if user account credentials are provided
		if let (Some(cid), Some(sec), Some(user), Some(pass)) = (
			get_setting("REDLIB_REDDIT_CLIENT_ID"),
			get_setting("REDLIB_REDDIT_CLIENT_SECRET"),
			get_setting("REDLIB_REDDIT_USERNAME"),
			get_setting("REDLIB_REDDIT_PASSWORD"),
		) {
			let backend = OauthBackendImpl::UserAuth(UserAuth::new(cid, sec, user, pass));
			let attempt = Self::new_with_timeout_with_backend(backend.clone()).await;
			match attempt {
				Ok(Ok(oauth)) => {
					info!("[✅] Successfully authenticated with Reddit account");
					return oauth;
				}
				Ok(Err(e)) => {
					error!("[⛔] Failed to authenticate with Reddit account: {:?}. Falling back to default auth...", e);
				}
				Err(_) => {
					error!("[⛔] User auth timed out. Falling back to default auth...");
				}
			}
		} else if let Some(token) = get_setting("REDLIB_REDDIT_BEARER_TOKEN") {
			let backend = OauthBackendImpl::FixedToken(FixedTokenAuth::new(token));
			if let Ok(Ok(oauth)) = Self::new_with_timeout_with_backend(backend).await {
				return oauth;
			}
		}

		// Try MobileSpoofAuth first, then fall back to GenericWebAuth
		let mut failure_count = 0;
		let mut backend = OauthBackendImpl::MobileSpoof(MobileSpoofAuth::new());

		loop {
			let attempt = Self::new_with_timeout_with_backend(backend.clone()).await;
			match attempt {
				Ok(Ok(oauth)) => {
					info!("[✅] Successfully created OAuth client");
					return oauth;
				}
				Ok(Err(e)) => {
					error!(
						"[⛔] Failed to create OAuth client: {}. Retrying in 5 seconds...",
						match e {
							AuthError::Wreq(error) => error.to_string(),
							AuthError::SerdeDeserialize(error) => error.to_string(),
							AuthError::Field((value, error)) => format!("{error}\n{value}"),
						}
					);
				}
				Err(_) => {
					error!("[⛔] Failed to create OAuth client before timeout. Retrying in 5 seconds...");
				}
			}

			failure_count += 1;

			// Switch to GenericWeb after 5 failures with MobileSpoof
			if matches!(backend, OauthBackendImpl::MobileSpoof(_)) && failure_count >= 5 {
				warn!("[🔄] MobileSpoofAuth failed 5 times. Falling back to GenericWebAuth...");
				backend = OauthBackendImpl::GenericWeb(GenericWebAuth::new());
			}

			// Crash after 10 total failures
			if failure_count >= 10 {
				error!("[⛔] Failed to create OAuth client (mobile + generic)");
				std::process::exit(1);
			}

			tokio::time::sleep(OAUTH_TIMEOUT).await;
		}
	}

	async fn new_with_timeout_with_backend(mut backend: OauthBackendImpl) -> Result<Result<Self, AuthError>, Elapsed> {
		timeout(OAUTH_TIMEOUT, async move {
			let response = backend.authenticate().await?;

			// Build headers_map from backend headers + Authorization header
			let mut headers_map = backend.get_headers();
			headers_map.insert("Authorization".to_owned(), format!("Bearer {}", response.token));
			headers_map.extend(response.additional_headers);

			Ok(Self {
				headers_map,
				expires_in: response.expires_in,
				backend,
			})
		})
		.await
	}

	pub fn user_agent(&self) -> &str {
		self.backend.user_agent()
	}

	pub fn is_authenticated(&self) -> bool {
		matches!(self.backend, OauthBackendImpl::UserAuth(_) | OauthBackendImpl::FixedToken(_))
	}
}

pub static POSTER_AUTH: LazyLock<tokio::sync::RwLock<Option<Oauth>>> = LazyLock::new(|| {
	tokio::sync::RwLock::new(None)
});

pub async fn init_poster_auth() {
	use crate::config::get_setting;
	if let (Some(cid), Some(sec), Some(user), Some(pass)) = (
		get_setting("REDLIB_POSTER_CLIENT_ID"),
		get_setting("REDLIB_POSTER_CLIENT_SECRET"),
		get_setting("REDLIB_POSTER_USERNAME"),
		get_setting("REDLIB_POSTER_PASSWORD"),
	) {
		info!("[🔑] Initializing poster OAuth for /u/{user}...");
		let backend = OauthBackendImpl::UserAuth(UserAuth::new(cid, sec, user, pass));
		match Oauth::new_with_timeout_with_backend(backend).await {
			Ok(Ok(oauth)) => {
				info!("[✍️] Poster OAuth client initialized successfully");
				let mut lock = POSTER_AUTH.write().await;
				*lock = Some(oauth);
			}
			Ok(Err(e)) => {
				error!("[⛔] Failed to initialize Poster OAuth: {:?}", e);
			}
			Err(_) => {
				error!("[⛔] Poster OAuth timeout");
			}
		}
	}
}

pub async fn get_poster_auth() -> Option<(String, String)> {
	{
		let lock = POSTER_AUTH.read().await;
		if let Some(client) = lock.as_ref() {
			let token = client.headers_map.get("Authorization").cloned().unwrap_or_default();
			let ua = client.user_agent().to_string();
			return Some((token, ua));
		}
	}

	init_poster_auth().await;

	let lock = POSTER_AUTH.read().await;
	lock.as_ref().map(|client| {
		let token = client.headers_map.get("Authorization").cloned().unwrap_or_default();
		let ua = client.user_agent().to_string();
		(token, ua)
	})
}

#[derive(Debug)]
enum AuthError {
	Wreq(wreq::Error),
	SerdeDeserialize(serde_json::Error),
	Field((serde_json::Value, &'static str)),
}

impl From<wreq::Error> for AuthError {
	fn from(err: wreq::Error) -> Self {
		AuthError::Wreq(err)
	}
}

impl From<serde_json::Error> for AuthError {
	fn from(err: serde_json::Error) -> Self {
		AuthError::SerdeDeserialize(err)
	}
}

pub async fn token_daemon() {
	// Monitor for refreshing token
	loop {
		// Get expiry time - be sure to not hold the read lock
		let expires_in = { OAUTH_CLIENT.load_full().expires_in };

		// sleep for the expiry time minus 2 minutes
		let duration = Duration::from_secs(expires_in - 120);

		info!("[⏳] Waiting for {duration:?} seconds before refreshing OAuth token...");

		tokio::time::sleep(duration).await;

		info!("[⌛] {duration:?} Elapsed! Refreshing OAuth token...");

		// Refresh token - in its own scope
		{
			force_refresh_token().await;
		}
	}
}

pub async fn force_refresh_token() {
	if OAUTH_IS_ROLLING_OVER.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
		trace!("Skipping refresh token roll over, already in progress");
		return;
	}

	trace!("Rolling over refresh token. Current rate limit: {}", OAUTH_RATELIMIT_REMAINING.load(Ordering::SeqCst));
	let new_client = Oauth::new().await;
	OAUTH_CLIENT.swap(new_client.into());
	OAUTH_RATELIMIT_REMAINING.store(99, Ordering::SeqCst);
	OAUTH_IS_ROLLING_OVER.store(false, Ordering::SeqCst);
}

#[derive(Debug, Clone, Default)]
struct Device {
	oauth_id: String,
	initial_headers: HashMap<String, String>,
	headers: HashMap<String, String>,
	user_agent: String,
}

// MobileSpoofAuth backend - spoofs an Android mobile device
#[derive(Debug, Clone)]
pub struct MobileSpoofAuth {
	device: Device,
	additional_headers: HashMap<String, String>,
}

impl MobileSpoofAuth {
	fn new() -> Self {
		Self {
			device: Device::new(),
			additional_headers: HashMap::new(),
		}
	}
}

impl OauthBackend for MobileSpoofAuth {
	async fn authenticate(&mut self) -> Result<OauthResponse, AuthError> {
		// Construct URL for OAuth token
		let url = format!("{AUTH_ENDPOINT}/auth/v2/oauth/access-token/loid");
		let mut builder = CLIENT.post(&url);

		// Add headers from spoofed client
		for (key, value) in &self.device.initial_headers {
			builder = builder.header(key, value);
		}
		// Set up HTTP Basic Auth - basically just the const OAuth ID's with no password,
		// Base64-encoded. https://en.wikipedia.org/wiki/Basic_access_authentication
		// This could be constant, but I don't think it's worth it. OAuth ID's can change
		// over time and we want to be flexible.
		let auth = general_purpose::STANDARD.encode(format!("{}:", self.device.oauth_id));
		builder = builder.header("Authorization", format!("Basic {auth}"));

		// Set JSON body. I couldn't tell you what this means. But that's what the client sends
		let json = json!({
				"scopes": ["*","email", "pii"]
		});

		trace!("Sending token request to {url}...");

		// Send request
		let resp = builder.json(&json).send().await?;

		trace!("Received response with status {} and length {:?}", resp.status(), resp.headers().get("content-length"));
		trace!("OAuth headers: {:#?}", resp.headers());

		// Parse headers - loid header _should_ be saved sent on subsequent token refreshes.
		// Technically it's not needed, but it's easy for Reddit API to check for this.
		// It's some kind of header that uniquely identifies the device.
		// Not worried about the privacy implications, since this is randomly changed
		// and really only as privacy-concerning as the OAuth token itself.
		if let Some(header) = resp.headers().get("x-reddit-loid") {
			let header_val: &wreq::header::HeaderValue = header;
			self.additional_headers.insert("x-reddit-loid".to_owned(), header_val.to_str().unwrap().to_string());
		}

		// Same with x-reddit-session
		if let Some(header) = resp.headers().get("x-reddit-session") {
			let header_val: &wreq::header::HeaderValue = header;
			self.additional_headers.insert("x-reddit-session".to_owned(), header_val.to_str().unwrap().to_string());
		}

		trace!("Serializing response...");

		// Serialize response
		let json: serde_json::Value = resp.json().await?;

		trace!("Accessing relevant fields...");

		// Save token and expiry
		let token = json
			.get("access_token")
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
			.as_str()
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
			.to_string();
		let expires_in = json
			.get("expires_in")
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in")))?
			.as_u64()
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in: as_u64")))?;

		info!("[✅] Success - Retrieved token \"{}...\", expires in {}", &token[..32], expires_in);

		Ok(OauthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.device.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		let mut headers = self.device.headers.clone();
		headers.extend(self.additional_headers.clone());
		headers
	}
}

// GenericWebAuth backend - simple web-based authentication
#[derive(Debug, Clone)]
pub struct GenericWebAuth {
	device_id: String,
	user_agent: String,
	additional_headers: HashMap<String, String>,
}

impl GenericWebAuth {
	fn new() -> Self {
		// Generate random 20-character alphanumeric device_id
		let device_id: String = (0..20)
			.map(|_| {
				let idx = fastrand::usize(..62);
				let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				chars[idx] as char
			})
			.collect();

		info!("[🔄] Using GenericWebAuth with device_id: \"{device_id}\"");

		Self {
			device_id,
			user_agent: fake_user_agent::get_rua().to_owned(),
			additional_headers: HashMap::new(),
		}
	}
}

impl OauthBackend for GenericWebAuth {
	async fn authenticate(&mut self) -> Result<OauthResponse, AuthError> {
		// Construct URL for OAuth token
		let url = "https://www.reddit.com/api/v1/access_token";
		let mut builder = CLIENT.post(url);

		// Add minimal headers
		builder = builder.header("Host", "www.reddit.com");
		builder = builder.header("User-Agent", &self.user_agent);
		builder = builder.header("Accept", "*/*");
		builder = builder.header("Accept-Language", "en-US,en;q=0.5");
		// builder = builder.header("Accept-Encoding", "gzip, deflate, br, zstd");
		builder = builder.header("Authorization", "Basic M1hmQkpXbGlIdnFBQ25YcmZJWWxMdzo=");
		builder = builder.header("Content-Type", "application/x-www-form-urlencoded");
		builder = builder.header("Sec-GPC", "1");
		builder = builder.header("Connection", "keep-alive");

		// Set up form body
		let body_str = format!("grant_type=https%3A%2F%2Foauth.reddit.com%2Fgrants%2Finstalled_client&device_id={}", self.device_id);

		trace!("Sending GenericWebAuth token request to {url}...");

		// Send request
		let resp: wreq::Response = builder.body(body_str).send().await?;

		trace!("Received response with status {} and length {:?}", resp.status(), resp.headers().get("content-length"));
		trace!("GenericWebAuth headers: {:#?}", resp.headers());

		// Parse headers - loid header _should_ be saved sent on subsequent token refreshes.
		// Technically it's not needed, but it's easy for Reddit API to check for this.
		// It's some kind of header that uniquely identifies the device.
		// Not worried about the privacy implications, since this is randomly changed
		// and really only as privacy-concerning as the OAuth token itself.
		if let Some(header) = resp.headers().get("x-reddit-loid") {
			let header_val: &wreq::header::HeaderValue = header;
			self.additional_headers.insert("x-reddit-loid".to_owned(), header_val.to_str().unwrap().to_string());
		}

		// Same with x-reddit-session
		if let Some(header) = resp.headers().get("x-reddit-session") {
			let header_val: &wreq::header::HeaderValue = header;
			self.additional_headers.insert("x-reddit-session".to_owned(), header_val.to_str().unwrap().to_string());
		}

		trace!("Serializing GenericWebAuth response...");

		// Serialize response
		let json: serde_json::Value = resp.json().await?;

		trace!("Accessing relevant fields...");

		// Parse response - access_token, token_type, device_id, expires_in, scope
		let token = json
			.get("access_token")
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
			.as_str()
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
			.to_string();
		let expires_in = json
			.get("expires_in")
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in")))?
			.as_u64()
			.ok_or_else(|| AuthError::Field((json.clone(), "expires_in: as_u64")))?;

		info!(
			"[✅] GenericWebAuth success - Retrieved token \"{}...\", expires in {}",
			&token[..32.min(token.len())],
			expires_in
		);

		// Insert a few necessary headers
		self.additional_headers.insert("Origin".to_owned(), "https://www.reddit.com".to_owned());
		self.additional_headers.insert("User-Agent".to_owned(), self.user_agent.to_owned());

		Ok(OauthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		self.additional_headers.clone()
	}
}

impl Device {
	fn android() -> Self {
		// Generate uuid
		let uuid = uuid::Uuid::new_v4().to_string();

		// Generate random user-agent
		let android_app_version = choose(ANDROID_APP_VERSION_LIST).to_string();
		let android_version = fastrand::u8(9..=14);

		let android_user_agent = format!("Reddit/{android_app_version}/Android {android_version}");

		let qos = fastrand::u32(1000..=100_000);
		let qos: f32 = qos as f32 / 1000.0;
		let qos = format!("{qos:.3}");

		let codecs = TextGenerator::new().generate("available-codecs=video/avc, video/hevc{, video/x-vnd.on2.vp9|}");

		// Android device headers
		let headers: HashMap<String, String> = HashMap::from([
			("User-Agent".into(), android_user_agent.clone()),
			("x-reddit-retry".into(), "algo=no-retries".into()),
			("x-reddit-compression".into(), "1".into()),
			("x-reddit-qos".into(), qos),
			("x-reddit-media-codecs".into(), codecs),
			("Content-Type".into(), "application/json; charset=UTF-8".into()),
			("client-vendor-id".into(), uuid.clone()),
			("X-Reddit-Device-Id".into(), uuid.clone()),
		]);

		info!("[🔄] Spoofing Android client with headers: {headers:?}, uuid: \"{uuid}\", and OAuth ID \"{REDDIT_ANDROID_OAUTH_CLIENT_ID}\"");

		Self {
			oauth_id: REDDIT_ANDROID_OAUTH_CLIENT_ID.to_string(),
			headers: headers.clone(),
			initial_headers: headers,
			user_agent: android_user_agent,
		}
	}
	fn new() -> Self {
		// See https://github.com/redlib-org/redlib/issues/8
		Self::android()
	}
}

fn choose<T: Copy>(list: &[T]) -> T {
	*fastrand::choose_multiple(list.iter(), 1)[0]
}

// UserAuth backend - authenticates with user's own Reddit script app credentials
#[derive(Debug, Clone)]
pub struct UserAuth {
	client_id: String,
	client_secret: String,
	username: String,
	password: String,
	user_agent: String,
	additional_headers: HashMap<String, String>,
}

impl UserAuth {
	pub fn new(client_id: String, client_secret: String, username: String, password: String) -> Self {
		let user_agent = format!("Redlib/0.40.0 (by /u/{username})");
		info!("[👤] Initializing UserAuth with Reddit account /u/{username}");
		Self {
			client_id,
			client_secret,
			username,
			password,
			user_agent,
			additional_headers: HashMap::new(),
		}
	}
}

impl OauthBackend for UserAuth {
	async fn authenticate(&mut self) -> Result<OauthResponse, AuthError> {
		let url = "https://www.reddit.com/api/v1/access_token";
		let mut builder = CLIENT.post(url);

		let auth = general_purpose::STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));
		builder = builder.header("Host", "www.reddit.com");
		builder = builder.header("Authorization", format!("Basic {auth}"));
		builder = builder.header("User-Agent", &self.user_agent);
		builder = builder.header("Content-Type", "application/x-www-form-urlencoded");
		builder = builder.header("Accept", "*/*");

		let encoded_user: String = url::form_urlencoded::byte_serialize(self.username.as_bytes()).collect();
		let encoded_pass: String = url::form_urlencoded::byte_serialize(self.password.as_bytes()).collect();
		let body_str = format!("grant_type=password&username={encoded_user}&password={encoded_pass}");

		trace!("Sending UserAuth token request to {url}...");

		let resp: wreq::Response = builder.body(body_str).send().await?;
		let json: serde_json::Value = resp.json().await?;

		let token = json
			.get("access_token")
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
			.as_str()
			.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
			.to_string();
		let expires_in = json
			.get("expires_in")
			.and_then(|v| v.as_u64())
			.unwrap_or(3600);

		info!(
			"[✅] UserAuth success - Retrieved authenticated token \"{}...\", expires in {}",
			&token[..32.min(token.len())],
			expires_in
		);

		self.additional_headers.insert("User-Agent".to_owned(), self.user_agent.to_owned());

		Ok(OauthResponse {
			token,
			expires_in,
			additional_headers: self.additional_headers.clone(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		self.additional_headers.clone()
	}
}

// FixedTokenAuth backend - uses a static bearer token
#[derive(Debug, Clone)]
pub struct FixedTokenAuth {
	token: String,
	user_agent: String,
}

impl FixedTokenAuth {
	pub fn new(token: String) -> Self {
		info!("[🔑] Initializing FixedTokenAuth with provided Bearer token");
		Self {
			token,
			user_agent: fake_user_agent::get_rua().to_owned(),
		}
	}
}

impl OauthBackend for FixedTokenAuth {
	async fn authenticate(&mut self) -> Result<OauthResponse, AuthError> {
		Ok(OauthResponse {
			token: self.token.clone(),
			expires_in: 86400 * 365,
			additional_headers: HashMap::new(),
		})
	}

	fn user_agent(&self) -> &str {
		&self.user_agent
	}

	fn get_headers(&self) -> HashMap<String, String> {
		let mut headers = HashMap::new();
		headers.insert("User-Agent".to_string(), self.user_agent.clone());
		headers
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test(flavor = "multi_thread")]
	async fn test_mobile_spoof_backend() {
		// Test MobileSpoofAuth backend specifically
		let mut backend = MobileSpoofAuth::new();
		let response = backend.authenticate().await;
		assert!(response.is_ok());
		let response = response.unwrap();
		assert!(!response.token.is_empty());
		assert!(response.expires_in > 0);
		assert!(!backend.user_agent().is_empty());
		assert!(!backend.get_headers().is_empty());
	}

	#[tokio::test(flavor = "multi_thread")]
	#[ignore = "todolol"]
	async fn test_generic_web_backend() {
		// Test GenericWebAuth backend specifically
		let mut backend = GenericWebAuth::new();
		let response = backend.authenticate().await;
		assert!(response.is_ok());
		let response = response.unwrap();
		assert!(!response.token.is_empty());
		assert!(response.expires_in > 0);
		assert!(!backend.user_agent().is_empty());
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_oauth_client() {
		// Integration test - tests the overall Oauth client
		assert!(OAUTH_CLIENT.load_full().headers_map.contains_key("Authorization"));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_oauth_client_refresh() {
		force_refresh_token().await;
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_oauth_token_exists() {
		let client = OAUTH_CLIENT.load_full();
		let auth_header = client.headers_map.get("Authorization").unwrap();
		assert!(auth_header.starts_with("Bearer "));
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_oauth_headers_len() {
		assert!(OAUTH_CLIENT.load_full().headers_map.len() >= 3);
	}

	#[test]
	fn test_creating_device() {
		Device::new();
	}

	#[test]
	fn test_creating_backends() {
		// Test that all backends can be created
		MobileSpoofAuth::new();
		GenericWebAuth::new();
		UserAuth::new("id".into(), "sec".into(), "user".into(), "pass".into());
		FixedTokenAuth::new("tok".into());
	}
}
