use crate::error::Result;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyscallId {
    NtClose,
    NtCreateFile,
    NtOpenFile,
    NtReadFile,
    NtWriteFile,
    NtQueryInformationFile,
    NtSetInformationFile,
    NtQueryDirectoryFile,
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtProtectVirtualMemory,
    NtQueryVirtualMemory,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    NtCreateProcessEx,
    NtCreateThreadEx,
    NtTerminateProcess,
    NtTerminateThread,
    NtQueryInformationProcess,
    NtQueryInformationThread,
    NtSetInformationThread,
    NtWaitForSingleObject,
    NtWaitForMultipleObjects,
    NtCreateEvent,
    NtSetEvent,
    NtResetEvent,
    NtCreateMutant,
    NtReleaseMutant,
    NtCreateSemaphore,
    NtReleaseSemaphore,
    NtOpenKey,
    NtCreateKey,
    NtQueryValueKey,
    NtSetValueKey,
    NtDeleteKey,
    NtEnumerateKey,
    NtEnumerateValueKey,
    NtDuplicateObject,
    // win32k
    NtGdiCreateCompatibleDC,
    NtGdiBitBlt,
    NtUserCreateWindowEx,
    NtUserShowWindow,
    NtUserMessageCall,
    NtUserDestroyWindow,
    Unknown(u32),
}

impl SyscallId {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "NtClose" => Some(Self::NtClose),
            "NtCreateFile" => Some(Self::NtCreateFile),
            "NtOpenFile" => Some(Self::NtOpenFile),
            "NtReadFile" => Some(Self::NtReadFile),
            "NtWriteFile" => Some(Self::NtWriteFile),
            "NtQueryInformationFile" => Some(Self::NtQueryInformationFile),
            "NtSetInformationFile" => Some(Self::NtSetInformationFile),
            "NtQueryDirectoryFile" => Some(Self::NtQueryDirectoryFile),
            "NtAllocateVirtualMemory" => Some(Self::NtAllocateVirtualMemory),
            "NtFreeVirtualMemory" => Some(Self::NtFreeVirtualMemory),
            "NtProtectVirtualMemory" => Some(Self::NtProtectVirtualMemory),
            "NtQueryVirtualMemory" => Some(Self::NtQueryVirtualMemory),
            "NtMapViewOfSection" => Some(Self::NtMapViewOfSection),
            "NtUnmapViewOfSection" => Some(Self::NtUnmapViewOfSection),
            "NtCreateProcessEx" => Some(Self::NtCreateProcessEx),
            "NtCreateThreadEx" => Some(Self::NtCreateThreadEx),
            "NtTerminateProcess" => Some(Self::NtTerminateProcess),
            "NtTerminateThread" => Some(Self::NtTerminateThread),
            "NtQueryInformationProcess" => Some(Self::NtQueryInformationProcess),
            "NtQueryInformationThread" => Some(Self::NtQueryInformationThread),
            "NtSetInformationThread" => Some(Self::NtSetInformationThread),
            "NtWaitForSingleObject" => Some(Self::NtWaitForSingleObject),
            "NtWaitForMultipleObjects" => Some(Self::NtWaitForMultipleObjects),
            "NtCreateEvent" => Some(Self::NtCreateEvent),
            "NtSetEvent" => Some(Self::NtSetEvent),
            "NtResetEvent" => Some(Self::NtResetEvent),
            "NtCreateMutant" => Some(Self::NtCreateMutant),
            "NtReleaseMutant" => Some(Self::NtReleaseMutant),
            "NtCreateSemaphore" => Some(Self::NtCreateSemaphore),
            "NtReleaseSemaphore" => Some(Self::NtReleaseSemaphore),
            "NtOpenKey" => Some(Self::NtOpenKey),
            "NtCreateKey" => Some(Self::NtCreateKey),
            "NtQueryValueKey" => Some(Self::NtQueryValueKey),
            "NtSetValueKey" => Some(Self::NtSetValueKey),
            "NtDeleteKey" => Some(Self::NtDeleteKey),
            "NtEnumerateKey" => Some(Self::NtEnumerateKey),
            "NtEnumerateValueKey" => Some(Self::NtEnumerateValueKey),
            "NtDuplicateObject" => Some(Self::NtDuplicateObject),
            "NtGdiCreateCompatibleDC" => Some(Self::NtGdiCreateCompatibleDC),
            "NtGdiBitBlt" => Some(Self::NtGdiBitBlt),
            "NtUserCreateWindowEx" => Some(Self::NtUserCreateWindowEx),
            "NtUserShowWindow" => Some(Self::NtUserShowWindow),
            "NtUserMessageCall" => Some(Self::NtUserMessageCall),
            "NtUserDestroyWindow" => Some(Self::NtUserDestroyWindow),
            _ => None,
        }
    }
}

pub struct SyscallTable {
    nt: HashMap<u32, SyscallId>,
    win32k: HashMap<u32, SyscallId>,
}

#[derive(Deserialize)]
struct SyscallConfig {
    nt: HashMap<String, u32>,
    #[serde(default)]
    win32k: HashMap<String, u32>,
}

impl SyscallTable {
    pub fn load_from_toml(data: &str) -> Result<Self> {
        let config: SyscallConfig = toml::from_str(data)?;
        let mut nt = HashMap::new();
        let mut win32k = HashMap::new();

        for (name, nr) in &config.nt {
            if let Some(id) = SyscallId::from_name(name) {
                nt.insert(*nr, id);
            }
        }
        for (name, nr) in &config.win32k {
            if let Some(id) = SyscallId::from_name(name) {
                win32k.insert(*nr, id);
            }
        }
        Ok(Self { nt, win32k })
    }

    pub fn lookup(&self, nr: u32) -> SyscallId {
        if nr >= 0x1000 {
            self.win32k
                .get(&nr)
                .copied()
                .unwrap_or(SyscallId::Unknown(nr))
        } else {
            self.nt.get(&nr).copied().unwrap_or(SyscallId::Unknown(nr))
        }
    }
}
