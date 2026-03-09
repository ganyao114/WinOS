// file_io_module.rs — HandlerModule impl for file I/O opcodes
//
// Registers: OP_OPEN, OP_READ, OP_WRITE, OP_CLOSE, OP_STAT,
//            OP_READDIR, OP_NOTIFY_DIR, OP_MMAP, OP_MUNMAP

use std::sync::{Arc, RwLock};
use winemu_shared::hostcall as hc;

use super::super::handlers::{self, HandlerCtx, MAX_IO_SIZE};
use super::super::registry::{HandlerModule, OpcodeEntry};
use super::super::types::WorkerPayload;
use crate::memory::GuestMemory;
use winemu_core::addr::Gpa;

// ── helpers ───────────────────────────────────────────────────────────────────

fn no_async(_args: [u64; 4]) -> bool { false }
fn always_async(_args: [u64; 4]) -> bool { true }
fn large_io_async(args: [u64; 4]) -> bool { (args[2] as usize) >= 128 * 1024 }
fn large_mmap_async(args: [u64; 4]) -> bool { (args[2] as usize) >= 2 * 1024 * 1024 }

// ── handler fns ───────────────────────────────────────────────────────────────

fn h_open(ctx: &HandlerCtx<'_>, args: [u64; 4], payload: Option<&WorkerPayload>) -> (u64, u64) {
    let path = payload.and_then(|p| {
        if let WorkerPayload::Path(s) = p { Some(s.as_ref()) } else { None }
    });
    handlers::execute_open(ctx, args, path)
}

fn h_read(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_read(ctx, args)
}

fn h_write(ctx: &HandlerCtx<'_>, args: [u64; 4], payload: Option<&WorkerPayload>) -> (u64, u64) {
    let bytes = payload.and_then(|p| {
        if let WorkerPayload::Bytes(b) = p { Some(b.as_ref()) } else { None }
    });
    handlers::execute_write(ctx, args, bytes)
}

fn h_close(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_close(ctx, args)
}

fn h_stat(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_stat(ctx, args)
}

fn h_readdir(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_readdir(ctx, args)
}

fn h_notify_dir(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_notify_dir(ctx, args)
}

fn h_mmap(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_mmap(ctx, args)
}

fn h_munmap(ctx: &HandlerCtx<'_>, args: [u64; 4], _: Option<&WorkerPayload>) -> (u64, u64) {
    handlers::execute_munmap(ctx, args)
}

// ── payload preparers ─────────────────────────────────────────────────────────

fn prep_open(
    memory: &Arc<RwLock<GuestMemory>>,
    args: [u64; 4],
) -> Result<WorkerPayload, (u64, u64)> {
    let path = handlers::decode_guest_path(memory, args[0], args[1] as usize)?;
    Ok(WorkerPayload::Path(path.into_boxed_str()))
}

fn prep_write(
    memory: &Arc<RwLock<GuestMemory>>,
    args: [u64; 4],
) -> Result<WorkerPayload, (u64, u64)> {
    let len = args[2] as usize;
    if len == 0 {
        return Ok(WorkerPayload::Bytes(Box::new([])));
    }
    if len > MAX_IO_SIZE {
        return Err((hc::HC_INVALID, 0));
    }
    let data = {
        let mem = memory.read().unwrap();
        mem.read_bytes(Gpa(args[1]), len).to_vec().into_boxed_slice()
    };
    Ok(WorkerPayload::Bytes(data))
}

// ── module ────────────────────────────────────────────────────────────────────

pub struct FileIoModule;

static ENTRIES: &[OpcodeEntry] = &[
    OpcodeEntry {
        opcode: hc::OP_OPEN,
        handler: h_open,
        async_eligible: always_async,
        prepare_payload: Some(prep_open),
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_READ,
        handler: h_read,
        async_eligible: large_io_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_WRITE,
        handler: h_write,
        async_eligible: large_io_async,
        prepare_payload: Some(prep_write),
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_CLOSE,
        handler: h_close,
        async_eligible: no_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_STAT,
        handler: h_stat,
        async_eligible: always_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_READDIR,
        handler: h_readdir,
        async_eligible: always_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_NOTIFY_DIR,
        handler: h_notify_dir,
        async_eligible: always_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_MMAP,
        handler: h_mmap,
        async_eligible: large_mmap_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
    OpcodeEntry {
        opcode: hc::OP_MUNMAP,
        handler: h_munmap,
        async_eligible: no_async,
        prepare_payload: None,
        requires_main_thread: false,
    },
];

impl HandlerModule for FileIoModule {
    fn opcodes(&self) -> &[OpcodeEntry] {
        ENTRIES
    }
}
