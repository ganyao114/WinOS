use object::{Object, ObjectSymbol, SymbolKind};
use rustc_demangle::demangle;
use std::path::{Path, PathBuf};

const DEFAULT_KERNEL_ELF_PATH: &str =
    "winemu-kernel/target/aarch64-unknown-none/release/winemu-kernel";

#[derive(Clone, Debug)]
struct KernelSymbol {
    address: u64,
    size: u64,
    name: String,
}

pub struct SymbolMatch<'a> {
    pub symbol: &'a str,
    pub symbol_addr: u64,
    pub offset: u64,
}

pub struct KernelSymbolizer {
    path: PathBuf,
    symbols: Vec<KernelSymbol>,
}

impl KernelSymbolizer {
    pub fn load_default() -> Option<Self> {
        let path = std::env::var("WINEMU_GUEST_DEBUG_KERNEL_ELF")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KERNEL_ELF_PATH));
        match Self::load(&path) {
            Ok(symbolizer) => Some(symbolizer),
            Err(err) => {
                log::warn!(
                    "debugger: failed to load kernel symbols from {}: {}",
                    path.display(),
                    err
                );
                None
            }
        }
    }

    pub fn lookup(&self, addr: u64) -> Option<SymbolMatch<'_>> {
        let idx = match self
            .symbols
            .binary_search_by_key(&addr, |symbol| symbol.address)
        {
            Ok(idx) => idx,
            Err(0) => return None,
            Err(idx) => idx - 1,
        };
        let symbol = self.symbols.get(idx)?;
        if symbol.size != 0 && addr >= symbol.address.saturating_add(symbol.size) {
            return None;
        }
        Some(SymbolMatch {
            symbol: &symbol.name,
            symbol_addr: symbol.address,
            offset: addr.saturating_sub(symbol.address),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|err| err.to_string())?;
        let file = object::File::parse(&*data).map_err(|err| err.to_string())?;
        let mut symbols = Vec::new();
        for symbol in file.symbols() {
            if symbol.address() == 0 {
                continue;
            }
            if !matches!(symbol.kind(), SymbolKind::Text | SymbolKind::Unknown) {
                continue;
            }
            let Ok(name) = symbol.name() else {
                continue;
            };
            let name = demangle(name).to_string();
            symbols.push(KernelSymbol {
                address: symbol.address(),
                size: symbol.size(),
                name,
            });
        }
        symbols.sort_by_key(|symbol| symbol.address);
        symbols.dedup_by_key(|symbol| symbol.address);
        if symbols.is_empty() {
            return Err("no symbols found".to_string());
        }
        Ok(Self {
            path: path.to_path_buf(),
            symbols,
        })
    }
}
