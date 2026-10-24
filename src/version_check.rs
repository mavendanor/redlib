use crate::client::CLIENT;
use log::{error, info};
use serde::Serialize;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

pub const FORK_REPO: &str = "mavendanor/redlib";
pub const UPSTREAM_REPO: &str = "redlib-org/redlib";

#[derive(Clone, Debug, Serialize)]
pub struct VersionInfo {
	pub base_version: String,
	pub latest_upstream: Option<String>,
	pub is_up_to_date: bool,
	pub has_update: bool,
	pub is_checked: bool,
}

impl VersionInfo {
	pub fn latest_display(&self) -> String {
		match &self.latest_upstream {
			Some(v) => format!("v{v}"),
			None => "Verificando...".to_string(),
		}
	}

	pub fn status_display(&self) -> String {
		if self.has_update {
			if let Some(v) = &self.latest_upstream {
				format!("Actualización disponible (v{v})")
			} else {
				"Actualización disponible".to_string()
			}
		} else if self.is_checked {
			"Al día con la versión oficial".to_string()
		} else {
			"Verificando estado...".to_string()
		}
	}
}

static VERSION_STATE: LazyLock<Arc<RwLock<VersionInfo>>> = LazyLock::new(|| {
	Arc::new(RwLock::new(VersionInfo {
		base_version: env!("CARGO_PKG_VERSION").to_string(),
		latest_upstream: None,
		is_up_to_date: false,
		has_update: false,
		is_checked: false,
	}))
});

pub fn get_version_info() -> VersionInfo {
	VERSION_STATE.read().map(|s| s.clone()).unwrap_or_else(|_| VersionInfo {
		base_version: env!("CARGO_PKG_VERSION").to_string(),
		latest_upstream: None,
		is_up_to_date: false,
		has_update: false,
		is_checked: false,
	})
}

pub fn spawn_version_checker() {
	tokio::spawn(async move {
		// Run initial check 3 seconds after startup
		tokio::time::sleep(Duration::from_secs(3)).await;
		loop {
			check_upstream_version().await;
			// Re-check every 4 hours
			tokio::time::sleep(Duration::from_secs(4 * 3600)).await;
		}
	});
}

async fn check_upstream_version() {
	let url = "https://api.github.com/repos/redlib-org/redlib/releases/latest";
	info!("[🏷️] Verificando versión oficial más reciente en GitHub ({url})...");

	let req = CLIENT
		.get(url)
		.header("User-Agent", "Redlib-Fork-Version-Checker")
		.header("Accept", "application/vnd.github.v3+json");

	match req.send().await {
		Ok(resp) => {
			if resp.status().is_success() {
				match resp.text().await {
					Ok(text) => {
						if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
							if let Some(tag) = json.get("tag_name").and_then(|t| t.as_str()) {
								let latest = tag.trim().trim_start_matches('v').to_string();
								let base = env!("CARGO_PKG_VERSION");
								let has_update = latest != base;
								let is_up_to_date = latest == base;

								info!("[🏷️] Versión upstream: v{latest} | Versión base fork: v{base} | Al día: {is_up_to_date}");

								if let Ok(mut state) = VERSION_STATE.write() {
									state.latest_upstream = Some(latest);
									state.has_update = has_update;
									state.is_up_to_date = is_up_to_date;
									state.is_checked = true;
								}
								return;
							}
						}
					}
					Err(e) => {
						error!("[⚠️] Error leyendo respuesta de GitHub Releases: {e}");
					}
				}
			} else {
				error!("[⚠️] GitHub Releases API devolvió status: {}", resp.status());
			}
		}
		Err(e) => {
			error!("[⚠️] Error conectando a GitHub Releases API: {e}");
		}
	}
}
