# Phase 3 — 图形 / 音频 / 输入 (第 17-24 周)

## 目标

能运行 Notepad.exe（ARM64 Windows 版），窗口正常显示，键盘输入正常；能运行使用 D3D11 的简单程序。

---

## P3-1: win32u syscall 拦截 + 窗口管理 (第 17-19 周)

### 架构

win32u.dll 通过 win32k syscall（0x1000+）与 Guest Kernel 通信。Guest Kernel 的 win32k 分发层将这些 syscall 转为 **hypercall**，跨越 VM 边界调用 Host 原生窗口系统。

```
Guest:  GDI App → win32u.dll (PE，不修改)
                      │ win32k syscall (SVC #0, x8 = 0x1000+)
                      ▼
            Guest Kernel win32k 分发层
                      │ hypercall (HVC #0)
                      ▼
Host:   win32u handler → macOS NSWindow/NSView
                       → Linux Wayland xdg_surface
```

### win32u shim (C)

```c
/* guest/win32u-shim/win32u_shim.c */

/* 窗口管理 */
HWND NtUserCreateWindowEx(DWORD ex_style, ...) {
    struct NtUserCreateWindowEx_params p = { ex_style, ... };
    return (HWND)hypercall(0x0500, (uint64_t)&p, 0, 0);
}

BOOL NtUserShowWindow(HWND hwnd, int cmd) {
    return (BOOL)hypercall(0x0501, (uint64_t)hwnd, cmd, 0);
}

BOOL NtUserDestroyWindow(HWND hwnd) {
    return (BOOL)hypercall(0x0502, (uint64_t)hwnd, 0, 0);
}

LRESULT NtUserMessageCall(HWND hwnd, UINT msg,
                           WPARAM wp, LPARAM lp, ...) {
    struct NtUserMessageCall_params p = { hwnd, msg, wp, lp, ... };
    return (LRESULT)hypercall(0x0503, (uint64_t)&p, 0, 0);
}

/* GDI */
HDC NtGdiCreateCompatibleDC(HDC hdc) {
    return (HDC)hypercall(0x0510, (uint64_t)hdc, 0, 0);
}

BOOL NtGdiBitBlt(HDC dst, int x, int y, int w, int h,
                  HDC src, int sx, int sy, DWORD rop) {
    struct NtGdiBitBlt_params p = { dst, x, y, w, h, src, sx, sy, rop };
    return (BOOL)hypercall(0x0511, (uint64_t)&p, 0, 0);
}
```

### Host 侧窗口管理

```rust
// crates/winemu-vmm/src/hypercall/win32u.rs

pub struct WindowManager {
    // HWND (guest) → NativeWindow (host)
    windows: HashMap<u64, NativeWindow>,
    // 共享内存帧缓冲：GDI 输出写入此处，定时 blit 到原生窗口
    framebuffers: HashMap<u64, SharedFramebuffer>,
}

pub fn handle_create_window(
    guest_mem: &GuestMemory,
    args: [u64; 6],
    wm: &mut WindowManager,
) -> u64 {
    let params = guest_mem.read_struct::<NtUserCreateWindowExParams>(Gpa(args[0]));
    let title = guest_mem.read_unicode_string(Gpa(params.window_name));

    let native = NativeWindow::create(&title, params.width, params.height);
    let hwnd = wm.next_hwnd();
    wm.windows.insert(hwnd, native);
    hwnd
}
```

### 共享内存帧缓冲（GDI 输出）

```rust
// crates/winemu-vmm/src/devices/framebuffer.rs

pub struct SharedFramebuffer {
    // 映射到 Guest 物理内存的共享页
    pub gpa: Gpa,
    pub width: u32,
    pub height: u32,
    pub stride: u32,   // bytes per row
    pub format: PixelFormat,
    pub data: Arc<Mutex<Vec<u8>>>,
}

// Host 定时器（每 16ms）将帧缓冲 blit 到原生窗口
pub fn start_blit_loop(wm: Arc<Mutex<WindowManager>>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(16));
            let wm = wm.lock();
            for (hwnd, fb) in &wm.framebuffers {
                if let Some(win) = wm.windows.get(hwnd) {
                    win.blit(fb);
                }
            }
        }
    });
}
```

### macOS 原生窗口 (Objective-C bridge)

```rust
// crates/winemu-vmm/src/platform/macos/window.rs

#[cfg(target_os = "macos")]
pub struct NativeWindow {
    ns_window: *mut objc::runtime::Object,
    ns_view: *mut objc::runtime::Object,
}

#[cfg(target_os = "macos")]
impl NativeWindow {
    pub fn create(title: &str, w: u32, h: u32) -> Self {
        unsafe {
            // NSWindow + NSView，在主线程创建
            // 使用 dispatch_async(dispatch_get_main_queue(), ...)
            todo!("objc bridge")
        }
    }

    pub fn blit(&self, fb: &SharedFramebuffer) {
        // CGBitmapContext → CGImage → NSView drawRect
        todo!()
    }
}
```

### Linux 原生窗口 (Wayland)

```rust
// crates/winemu-vmm/src/platform/linux/window.rs

#[cfg(target_os = "linux")]
pub struct NativeWindow {
    surface: wayland_client::protocol::wl_surface::WlSurface,
    shm_pool: wayland_client::protocol::wl_shm_pool::WlShmPool,
}
```

### P3-1 验收

- [ ] `NtUserCreateWindowEx` 在 Host 创建原生窗口
- [ ] `NtGdiBitBlt` 将像素写入共享帧缓冲，定时 blit 到窗口
- [ ] Notepad.exe 窗口正常显示
- [ ] 窗口关闭事件正确传递给 Guest

---

## P3-2: winevulkan unix call → hypercall shim (第 19-21 周)

### 架构

winevulkan 的 unix call 路径（不是 syscall）直接替换为 hypercall shim。DXVK 和 winevulkan PE 层完全不修改。

```
Guest:  DXVK (PE) → winevulkan.dll (PE) → unix call (hypercall shim)
                                                 │ HVC #0 (hypercall)
Host:   vulkan handler → libvulkan.so / MoltenVK → Metal / Vulkan 驱动
```

### winevulkan shim (C)

```c
/* guest/winevulkan-shim/winevulkan_shim.c */

/* Vulkan 命令通过共享内存传递（参数可能较大） */
VkResult vk_call(uint32_t cmd_id, void *params, size_t params_size) {
    struct VkCallHeader hdr = {
        .cmd_id = cmd_id,
        .params_size = params_size,
    };
    // 写入共享内存页
    memcpy(shared_vk_page, &hdr, sizeof(hdr));
    memcpy(shared_vk_page + sizeof(hdr), params, params_size);
    // MMIO doorbell 通知 Host
    *(volatile uint32_t *)VK_DOORBELL_ADDR = cmd_id;
    // 等待 completion（轮询 completion ring）
    return wait_vk_completion();
}

VkResult vkCreateInstance(const VkInstanceCreateInfo *ci,
                           const VkAllocationCallbacks *alloc,
                           VkInstance *inst) {
    struct VkCreateInstance_params p = { ci, alloc, inst };
    return vk_call(VK_CMD_CREATE_INSTANCE, &p, sizeof(p));
}
```

### Host 侧 Vulkan handler

```rust
// crates/winemu-vmm/src/hypercall/vulkan.rs

pub struct VulkanHandler {
    // Guest handle → Host handle 映射
    instances: HashMap<u64, ash::Instance>,
    devices: HashMap<u64, ash::Device>,
    swapchains: HashMap<u64, Swapchain>,
}

impl VulkanHandler {
    pub fn handle_mmio_doorbell(&mut self,
                                 guest_mem: &GuestMemory,
                                 cmd_id: u32) {
        let hdr = guest_mem.read_struct::<VkCallHeader>(VK_SHARED_PAGE_GPA);
        let params_gpa = VK_SHARED_PAGE_GPA.offset(size_of::<VkCallHeader>() as u64);

        match cmd_id {
            VK_CMD_CREATE_INSTANCE => self.create_instance(guest_mem, params_gpa),
            VK_CMD_CREATE_DEVICE   => self.create_device(guest_mem, params_gpa),
            VK_CMD_QUEUE_SUBMIT    => self.queue_submit(guest_mem, params_gpa),
            VK_CMD_PRESENT         => self.present(guest_mem, params_gpa),
            _ => log::warn!("unknown vk cmd {}", cmd_id),
        }
    }

    fn create_instance(&mut self, guest_mem: &GuestMemory, params_gpa: Gpa) {
        // 读取参数，调用真实 vkCreateInstance
        let entry = ash::Entry::linked();
        let instance = unsafe { entry.create_instance(&create_info, None) }.unwrap();
        let guest_handle = self.next_handle();
        self.instances.insert(guest_handle, instance);
        // 写回 guest handle
        guest_mem.write_u64(RESULT_GPA, guest_handle);
    }

    fn present(&mut self, guest_mem: &GuestMemory, params_gpa: Gpa) {
        // 将 swapchain image blit 到 Host 原生窗口 surface
        let params = guest_mem.read_struct::<VkPresentParams>(params_gpa);
        let swapchain = self.swapchains.get(&params.swapchain).unwrap();
        swapchain.present_to_native_window();
    }
}
```

### 共享内存布局

```
GPA 0x50000000 (VK_SHARED_PAGE):
  [0x000] VkCallHeader (cmd_id, params_size)
  [0x010] params data (可变长)
  [0x800] completion ring (VkResult + output data)

GPA 0x50001000 (VK_DOORBELL):
  MMIO write → 触发 Host 处理
```

### P3-2 验收

- [ ] `vkCreateInstance` / `vkCreateDevice` 正确映射到 Host
- [ ] 简单 Vulkan triangle demo 能渲染
- [ ] DXVK D3D11 triangle demo 能运行
- [ ] Present 正确显示到原生窗口

---

## P3-3: 输入事件 (第 21-22 周)

Host 捕获键盘/鼠标事件，通过共享内存 ring buffer 注入 Guest，无需 VM exit。

### 共享内存 Ring Buffer

```rust
// crates/winemu-core/src/input.rs

#[repr(C)]
pub struct InputRing {
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub _pad: [u8; 56],  // 填充到 64 字节，避免 false sharing
    pub events: [InputEvent; 256],
}

#[repr(C, u8)]
pub enum InputEvent {
    KeyDown       { vk: u16, scan: u16 },
    KeyUp         { vk: u16, scan: u16 },
    MouseMove     { x: i32, y: i32 },
    MouseButton   { button: u8, down: bool },
    MouseWheel    { delta: i16 },
    FocusGained,
    FocusLost,
}
```

### Host 侧事件注入

```rust
// crates/winemu-vmm/src/input/mod.rs

pub struct InputInjector {
    ring: Arc<Mutex<&'static mut InputRing>>,
}

impl InputInjector {
    pub fn push(&self, event: InputEvent) {
        let mut ring = self.ring.lock();
        let tail = ring.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % 256;
        if next_tail != ring.head.load(Ordering::Acquire) {
            ring.events[tail as usize] = event;
            ring.tail.store(next_tail, Ordering::Release);
            // 无需 VM exit，Guest 轮询 ring buffer
        }
    }
}
```

### macOS 事件捕获

```rust
// crates/winemu-vmm/src/platform/macos/input.rs

#[cfg(target_os = "macos")]
pub fn start_event_loop(injector: Arc<InputInjector>) {
    // NSEvent 监听，在主线程运行
    // 键盘: NSKeyDown / NSKeyUp → vk code 转换
    // 鼠标: NSMouseMoved / NSLeftMouseDown 等
    todo!("NSEvent monitoring")
}
```

### Guest 侧轮询

```rust
// winemu-kernel/src/io/input.rs

pub fn poll_input_events() {
    let ring = unsafe { &*(INPUT_RING_GVA as *const InputRing) };
    loop {
        let head = ring.head.load(Ordering::Acquire);
        let tail = ring.tail.load(Ordering::Relaxed);
        if head == tail { break; }

        let event = ring.events[head as usize];
        dispatch_input_event(event);
        ring.head.store((head + 1) % 256, Ordering::Release);
    }
}
```

### VK Code 映射

```rust
// crates/winemu-vmm/src/input/vk_map.rs

pub fn macos_keycode_to_vk(keycode: u16) -> u16 {
    match keycode {
        0x00 => 0x41, // A
        0x01 => 0x53, // S
        0x24 => 0x0D, // Return → VK_RETURN
        0x31 => 0x20, // Space → VK_SPACE
        0x35 => 0x1B, // Escape → VK_ESCAPE
        _ => 0,
    }
}
```

### P3-3 验收

- [ ] 键盘输入正确传递到 Guest（Notepad 能输入文字）
- [ ] 鼠标移动和点击正确
- [ ] 输入延迟 < 5ms（ring buffer 无 VM exit）

---

## P3-4: 音频 (第 22-23 周)

`winmm` / `mmdevapi` Unix lib 替换为 hypercall shim。

### 音频 shim (C)

```c
/* guest/audio-shim/audio_shim.c */

MMRESULT waveOutOpen(HWAVEOUT *hwo, UINT dev_id,
                     WAVEFORMATEX *fmt, ...) {
    struct WaveOutOpen_params p = { hwo, dev_id, fmt, ... };
    return (MMRESULT)hypercall(0x0600, (uint64_t)&p, 0, 0);
}

MMRESULT waveOutWrite(HWAVEOUT hwo, WAVEHDR *hdr, UINT size) {
    // 音频数据通过共享内存传递
    memcpy(audio_shared_buf, hdr->lpData, hdr->dwBufferLength);
    struct WaveOutWrite_params p = {
        .hwo = hwo,
        .length = hdr->dwBufferLength,
        .shared_buf_gpa = AUDIO_SHARED_BUF_GPA,
    };
    return (MMRESULT)hypercall(0x0601, (uint64_t)&p, 0, 0);
}
```

### Host 侧音频实现

```rust
// crates/winemu-vmm/src/hypercall/audio.rs

#[cfg(target_os = "macos")]
mod backend {
    use coreaudio::audio_unit::AudioUnit;

    pub struct AudioBackend {
        unit: AudioUnit,
        sample_rate: f64,
        channels: u32,
    }

    impl AudioBackend {
        pub fn write(&mut self, guest_mem: &GuestMemory,
                     shared_buf_gpa: Gpa, length: u32) {
            let data = guest_mem.read_bytes(shared_buf_gpa, length as usize);
            self.unit.write_pcm(&data);
        }
    }
}

#[cfg(target_os = "linux")]
mod backend {
    // PipeWire backend
    pub struct AudioBackend { /* ... */ }
}
```

### 共享内存音频缓冲

```
GPA 0x51000000 (AUDIO_SHARED_BUF):
  大小: 64KB（约 370ms @ 44100Hz 16bit stereo）
  Guest 写入 PCM 数据，Host 读取并送到音频设备
```

### P3-4 验收

- [ ] 能播放 WAV 文件（通过 `PlaySound`）
- [ ] 音频无明显卡顿（缓冲区足够）
- [ ] macOS CoreAudio 和 Linux PipeWire 均正常

---

## P3-5: Phase 3 整体验收 (第 23-24 周)

### 验收程序 1: Notepad.exe

```bash
winemu run notepad.exe
```

- [ ] 窗口正常显示，标题栏、菜单栏正确
- [ ] 键盘输入文字正常
- [ ] 鼠标点击菜单正常
- [ ] 文件保存/打开正常（通过 NtCreateFile）

### 验收程序 2: D3D11 Triangle

```bash
winemu run d3d11_triangle.exe
```

- [ ] 窗口显示彩色三角形
- [ ] 帧率 > 30fps
- [ ] 无 Vulkan validation error

### 验收程序 3: 音频播放

```bash
winemu run audio_test.exe
```

- [ ] 能播放 1kHz 正弦波 1 秒
- [ ] 无爆音/卡顿
