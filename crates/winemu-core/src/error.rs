use thiserror::Error;

#[derive(Debug, Error)]
pub enum WinemuError {
    #[error("hypervisor error: {0}")]
    Hypervisor(String),
    #[error("memory error: {0}")]
    Memory(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nt status: {0:#010x}")]
    NtStatus(u32),
    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, WinemuError>;
