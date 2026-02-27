#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod architecture;
mod registry_value;
mod registry_key;
mod registry_utils;
#[cfg(feature = "std")]
mod registry_parser;
#[cfg(feature = "std")]
mod registry_writer;
#[cfg(feature = "std")]
mod registry_comparator;
#[cfg(feature = "std")]
mod registry_patcher;
#[cfg(feature = "std")]
mod registry_text_diff;
#[cfg(feature = "std")]
mod registry_dsl;
#[cfg(feature = "std")]
mod registry_editor;

pub use architecture::Architecture;
pub use registry_value::{
    RegistryValue, RegistryValueData, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD,
    REG_SZ,
};
pub use registry_key::{KeyNode, RegistryKey};
#[cfg(feature = "std")]
pub use registry_key::RegistryKeyExt;
pub use registry_utils::*;
#[cfg(feature = "std")]
pub use registry_parser::{LoadResult, ParseError, RegistryParser};
#[cfg(feature = "std")]
pub use registry_writer::RegistryWriter;
#[cfg(feature = "std")]
pub use registry_comparator::{DiffResult, KeyPropertyChange, RegistryChange, RegistryComparator};
#[cfg(feature = "std")]
pub use registry_patcher::{PatchFailure, PatchOptions, PatchResult, RegistryPatcher};
#[cfg(feature = "std")]
pub use registry_text_diff::{TextDiffExporter, TextDiffParser};
#[cfg(feature = "std")]
pub use registry_dsl::{load_registry, modify_registry, registry, RegistryKeyDsl, RegistryResult};
#[cfg(feature = "std")]
pub use registry_editor::RegistryEditor;
