use std::path::PathBuf;
use dirs::home_dir;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub codex_home: PathBuf,
    pub chatgpt_base_url: String,
    pub model: String,
    pub user_instructions: Option<String>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let codex_home = find_codex_home();
        
        // Load user instructions from AGENTS.md
        let user_instructions = Self::load_instructions(Some(&codex_home));
        
        // Check if auth.json exists in ./local_auth directory (fallback)
        let local_auth_dir = std::env::current_dir()?.join("local_auth");
        let local_auth_file = local_auth_dir.join("auth.json");
        if local_auth_file.exists() {
            return Ok(Config {
                codex_home: local_auth_dir,
                chatgpt_base_url: "https://chatgpt.com/backend-api/codex".to_string(),
                model: "gpt-5".to_string(),
                user_instructions,
            });
        }
        // Check if auth.json exists in the current directory (legacy fallback)
        let current_dir_auth = std::env::current_dir()?.join("auth.json");
        if current_dir_auth.exists() {
            return Ok(Config {
                codex_home: std::env::current_dir()?,
                chatgpt_base_url: "https://chatgpt.com/backend-api/codex".to_string(),
                model: "gpt-5".to_string(),
                user_instructions,
            });
        }
        
        Ok(Config {
            codex_home,
            chatgpt_base_url: "https://chatgpt.com/backend-api/codex".to_string(),
            model: "gpt-5".to_string(), // Default, but can be changed to any gpt-5* variant
            user_instructions,
        })
    }

    fn load_instructions(codex_dir: Option<&std::path::Path>) -> Option<String> {
        let mut p = match codex_dir {
            Some(p) => p.to_path_buf(),
            None => return None,
        };

        p.push("AGENTS.md");
        std::fs::read_to_string(&p).ok().and_then(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        })
    }
}

fn find_codex_home() -> PathBuf {
    // Try to find codex home directory for Codex Proxy Server and Opencode integration
    if let Some(home) = home_dir() {
        // First check for .codex directory (Codex Proxy Server CLI compatibility)
        let codex_home = home.join(".codex");
        if codex_home.exists() {
            return codex_home;
        }
        
        // Then check for .opencode directory (Opencode integration default)
        let opencode_home = home.join(".opencode");
        if opencode_home.exists() {
            return opencode_home;
        }
    }
    
    // Fallback to current directory
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}