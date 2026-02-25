# WinEmu 实现计划索引

## 阶段总览

| 阶段 | 文档 | 周期 | 目标 |
|------|------|------|------|
| Phase 0 | [phase-0-infrastructure.md](phase-0-infrastructure.md) | 第 1-2 周 | Cargo workspace + 核心类型 + CI |
| Phase 1 | [phase-1-hypervisor.md](phase-1-hypervisor.md) | 第 3-8 周 | Hypervisor 抽象层 + 最小 Guest Kernel |
| Phase 2 | [phase-2-nt-subsystem.md](phase-2-nt-subsystem.md) | 第 9-16 周 | NT 子系统 + Wine DLL 集成 + Hello World |
| Phase 3 | [phase-3-graphics-audio-input.md](phase-3-graphics-audio-input.md) | 第 17-24 周 | 图形 / 音频 / 输入 |
| Phase 4 | [phase-4-compatibility-dbt.md](phase-4-compatibility-dbt.md) | 持续 | 兼容性提升 + FEX 跨架构 + iOS |

## 关键里程碑

```
Week 2  ── P0 完成: cargo build --workspace 全平台通过
Week 4  ── P1-1/P1-2/P1-3: HVF/KVM 后端单元测试通过
Week 6  ── P1-4: Guest Kernel 启动，MMU 开启，HYPERCALL_KERNEL_READY 收到
Week 8  ── P1-5: VMM 主循环，双向 hypercall 通信正常
Week 10 ── P2-1: PE 加载器，能加载静态 PE32+
Week 13 ── P2-4: ntdll hypercall shim，文件 I/O 通过 hypercall 代理
Week 16 ── P2-7: Hello World — winemu run hello.exe 输出正确
Week 19 ── P3-1: Notepad.exe 窗口显示
Week 21 ── P3-2: D3D11 triangle demo 运行
Week 24 ── P3-5: 图形/音频/输入全部验收通过
持续    ── P4: winetest 通过率 > 60%，FEX 跨架构，iOS 探索
```

## 依赖关系

```
P0 (核心类型)
 └── P1-1 (Hypervisor 抽象)
      ├── P1-2 (HVF 后端)
      ├── P1-3 (KVM 后端)
      └── P1-4 (Guest Kernel)
           └── P1-5 (VMM 主循环)
                └── P2-1 (PE 加载器)
                     ├── P2-2 (对象管理器)
                     │    └── P2-3 (进程/线程)
                     │         └── P2-4 (ntdll shim)
                     │              ├── P2-5 (同步原语)
                     │              ├── P2-6 (文件 I/O)
                     │              └── P2-7 (Hello World ✓)
                     └── P3-1 (win32u shim)
                          ├── P3-2 (winevulkan shim)
                          ├── P3-3 (输入)
                          ├── P3-4 (音频)
                          └── P3-5 (验收 ✓)
                               └── P4 (兼容性/DBT/iOS)
```

## 技术参考

- 架构文档: [../architecture.md](../architecture.md)
- Hypercall ABI: [../hypercall-abi.md](../hypercall-abi.md)
