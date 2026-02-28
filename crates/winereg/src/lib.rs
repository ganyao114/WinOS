#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod architecture;
#[cfg(feature = "std")]
mod registry_comparator;
#[cfg(feature = "std")]
mod registry_dsl;
#[cfg(feature = "std")]
mod registry_editor;
mod registry_key;
#[cfg(feature = "std")]
mod registry_parser;
#[cfg(feature = "std")]
mod registry_patcher;
#[cfg(feature = "std")]
mod registry_text_diff;
mod registry_utils;
mod registry_value;
#[cfg(feature = "std")]
mod registry_writer;

pub use architecture::Architecture;
#[cfg(feature = "std")]
pub use registry_comparator::{DiffResult, KeyPropertyChange, RegistryChange, RegistryComparator};
#[cfg(feature = "std")]
pub use registry_dsl::{load_registry, modify_registry, registry, RegistryKeyDsl, RegistryResult};
#[cfg(feature = "std")]
pub use registry_editor::RegistryEditor;
#[cfg(feature = "std")]
pub use registry_key::RegistryKeyExt;
pub use registry_key::{KeyNode, RegistryKey};
#[cfg(feature = "std")]
pub use registry_parser::{LoadResult, ParseError, RegistryParser};
#[cfg(feature = "std")]
pub use registry_patcher::{PatchFailure, PatchOptions, PatchResult, RegistryPatcher};
#[cfg(feature = "std")]
pub use registry_text_diff::{TextDiffExporter, TextDiffParser};
pub use registry_utils::*;
pub use registry_value::{
    RegistryValue, RegistryValueData, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ,
};
#[cfg(feature = "std")]
pub use registry_writer::RegistryWriter;
