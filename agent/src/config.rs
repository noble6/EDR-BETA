use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub api_url: String,
    pub api_key: String,
    pub agent_id: String,
    pub monitor_dir: String,
    pub quarantine_dir: String,
    pub cache_capacity: usize,
    pub offline_queue_path: String,
    /// Path to the YARA signature .yar file.
    /// Defaults to /opt/antivirus/signatures/signatures.yar if not set.
    pub signatures_path: Option<String>,
}

pub fn load_config(path: &str) -> Config {
    let content = fs::read_to_string(path).expect("Failed to read config.json");
    let config: Config = serde_json::from_str(&content).expect("Invalid config format");
    
    // Ensure directories exist
    let _ = fs::create_dir_all(&config.monitor_dir);
    let _ = fs::create_dir_all(&config.quarantine_dir);
    if let Some(parent) = Path::new(&config.offline_queue_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    
    config
}
