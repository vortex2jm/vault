use serde::{Deserialize, Serialize};
use wincode::{SchemaRead, SchemaWrite};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, SchemaWrite, SchemaRead, Zeroize)]
pub struct Entry {
    pub service: String,
    pub username: String,
    pub passwd: String,
    created_at: i64,
    updated_at: i64,
}

impl Entry {
    pub fn new(service: String, username: String, passwd: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            service,
            username,
            passwd,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update(&mut self, username: Option<String>, passwd: Option<String>) {
        let now = chrono::Utc::now().timestamp();
        if let Some(u) = username {
            self.username = u;
        }
        if let Some(p) = passwd {
            self.passwd = p;
        }
        self.updated_at = now;
    }
}

#[derive(Serialize, Deserialize, Clone, SchemaWrite, SchemaRead)]
pub struct VaultState {
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub cipher: Vec<u8>,
}

impl VaultState {
    pub fn new(salt: &[u8; 16]) -> Self {
        Self {
            salt: *salt,
            nonce: [0; 12],
            cipher: vec![],
        }
    }
}
