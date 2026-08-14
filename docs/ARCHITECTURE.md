# 工作原理与架构

本文描述 `frida-instr-trace` 当前实现的组件边界、启动时序、线程交接、指令采集和文本输出。项目只支持 native launcher 启动方式，只生成开源 unidbg `AssemblyCodeDumper` 风格文本。

面向日常使用和失败定位的说明见 [README](../README.md) 和 [排障指南](TROUBLESHOOTING.md)。

## 总体架构

```text
veh-injector.exe (launcher/controller)
  |
  | CreateProcessW(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)
  | CreateRemoteThread(LoadLibraryW)
  v
target.exe
  +-- veh-dll.dll
  |     +-- software breakpoint (int3)
  |     +-- vectored exception handler
  |     +-- named events + shared mapping
  |
  +-- Frida Gum / Stalker agent
        +-- Interceptor gate
        +-- instruction transform + callouts
        +-- register/memory/flow collection
                  |
                  | Frida send() batches
                  v
        frida-rva-trace (Python PID controller)
                  |
                  v
        UnidbgTextWriter -> trace.txt
```

Native launcher 是唯一用户入口。Python 控制器是 launcher 启动的内部组件，不负责创建目标进程。

## 组件职责

### Native launcher

路径：`native/veh-injector/veh-injector.cpp`

负责：

- 解析用户参数并推导默认模块、DLL、Python 控制器和输出路径。
- 使用 `CREATE_SUSPENDED | CREATE_NEW_CONSOLE` 创建目标。
- 创建跨进程命名事件。
- 通过远程 `LoadLibraryW` 注入 VEH DLL。
- 等待 DLL 的断点命中通知。
- 从共享映射读取命中线程 ID 和断点地址。
- 启动 `.venv\Scripts\frida-rva-trace.exe` 并传入 PID、线程和 gate 地址。
- 等待 Frida ready 事件及控制器退出。

Launcher 不解析指令，也不写 trace 内容。

### VEH DLL

路径：`native/veh-dll/veh-dll.cpp`

负责在 Frida 附加前建立一个稳定的线程交接点：

- 创建命名事件和共享内存。
- 安装 vectored exception handler。
- 解析触发模块、导出函数或模块内 RVA。
- 保存触发地址首字节并写入 `0xCC` 软件断点。
- 断点命中后恢复原字节和 `RIP`。
- 保存命中线程 ID 与断点地址。
- 暂停其他目标线程，等待 Frida 完成 Stalker 初始化。
- 收到 ready 事件后恢复其他线程并继续执行原指令。

默认触发点为 `ucrtbase.dll!__p___argv`，也支持 `--trigger-module` / `--trigger-symbol` 或 `--trigger-rva` 覆盖：

```text
FRIDA_TRACE_TRIGGER_MODULE
FRIDA_TRACE_TRIGGER_SYMBOL
FRIDA_TRACE_TRIGGER_RVA
```

触发模块和符号必须在 DLL 注入时已经可解析，否则远程 `LoadLibraryW` 会失败。

### Python PID 控制器

路径：`frida_instr_trace/cli.py`

负责：

- 附加 launcher 提供的 PID。
- 加载 JavaScript agent。
- 把模块边界、owner thread、gate 地址和 flush 配置传给 agent。
- agent 就绪后设置 native ready 事件。
- 接收批量指令记录并交给文本 writer。
- 在终点、进程退出、异常或用户中断时停止并分离 Frida。

控制器要求 `--pid` 和 `--module`，不提供 EXE 直启或追加输出。

### Frida Stalker agent

路径：`frida_instr_trace/agent/rva_trace.js`

负责运行时模块解析、线程跟踪和指令状态采集：

- 匹配 target/start/stop 模块并计算绝对边界地址。
- 在 VEH 断点地址安装 Interceptor gate。
- 从 gate 的 `onEnter` 回调调用 `Stalker.follow(options)`。
- 只记录命中起点的 owner thread。
- 根据 `target-only` 决定是否保留跨模块执行流。
- 解析指令字节、汇编、寄存器读写集合和内存操作数。
- 根据运行时上下文计算内存有效地址。
- 解析离开当前模块的控制转移目标。
- 按 `flush` 阈值向 Python 批量发送记录。

### 文本 writer

路径：`frida_instr_trace/unidbg_text.py`

负责把结构化记录渲染为唯一支持的输出格式。Writer 总是使用 `w` 模式打开文件，因此每次运行都会截断同名旧 trace。

## 启动与交接时序

```text
User        Launcher       Target/VEH DLL       Python        Frida agent
 |             |                  |                |               |
 | run         |                  |                |               |
 |-----------> | Create suspended |                |               |
 |             |----------------> |                |               |
 |             | inject DLL       |                |               |
 |             |----------------> | install VEH    |               |
 |             | resume target    | arm int3       |               |
 |             |----------------> |                |               |
 |             | wait hit         | execute int3   |               |
 |             | <--------------- | signal hit     |               |
 |             | read owner TID   | wait ready     |               |
 |             | start controller |                |               |
 |             |---------------------------------> | attach        |
 |             |                  |                |-------------> |
 |             |                  |                |  gate ready   |
 |             |                  | <--------------| signal ready  |
 |             |                  | resume threads |               |
 |             |                  | execute trigger|               |
 |             |                  |------------------------------> | onEnter
 |             |                  |                |               | Stalker.follow
 |             |                  |                | <-------------| trace batches
 |             |                  |                | write text    |
```

这个 gate 是必要的：目标线程在 VEH 中暂停时位于异常处理路径，Stalker 应从恢复后的真实触发函数入口开始，而不是从控制器任意选择的线程上下文开始。

## 跨进程同步协议

同步对象按目标 PID 命名：

| 对象 | 名称 | 方向 | 用途 |
| --- | --- | --- | --- |
| Hit event | `Local\InjectVehHit_<pid>` | DLL -> launcher | 通知软件断点已命中。 |
| Ready event | `Local\InjectVehFridaReady_<pid>` | Python -> DLL | 通知 agent 和 Stalker 已准备好。 |
| File mapping | `Local\InjectVehState_<pid>` | DLL -> launcher | 传递协议版本、owner TID 和断点地址。 |

共享结构当前版本为 `1`：

```cpp
struct SharedState {
    DWORD version;
    DWORD hitThreadId;
    uint64_t breakpointAddress;
};
```

Launcher 和 DLL 中的结构布局必须保持一致。修改时应同步升级和校验 `version`。

## 边界语义

绝对地址按模块运行时基址计算：

```text
absolute = module.base + rva
```

- `start-rva` 是 inclusive 精确起点。
- `start-rva=0` 表示起始模块内首条被观察到的指令。
- `stop-rva` 是 inclusive 精确终点，终点指令会写入 trace。
- `stop-rva=0` 表示等待进程退出。
- start 和 stop 可以位于不同模块。
- stop RVA 不要求大于 start RVA，是否停止只取决于实际执行流。
- 默认只接受命中 start 的 owner thread；其他线程不会写入 trace。

`target-only=1` 时只记录 target/start/stop 模块。Stalker 在首次进入目标代码后才启用非目标模块排除，避免线程从 CRT gate 进入目标模块之前被提前排除。

## 指令采集

Stalker transform 在基本块翻译期间分析静态信息，并插入运行时 callout：

1. Frida `Instruction.parse()` 提供地址、大小、字节、助记符和操作数。
2. agent 将寄存器别名归一化到 x64 通用寄存器。
3. `regsRead`、`regsWritten` 和操作数 access 标记转换为读写 bit mask。
4. 最多保留四个内存操作数描述。
5. 运行时 callout 使用 CPU context 计算有效地址和寄存器快照。
6. 控制转移指令解析寄存器、内存或栈中的实际目标。
7. 外部目标优先用模块导出表命名，再回退到 Frida debug symbol。

内存记录只包含访问类型、大小和有效地址，不读取或保存内存值。

## 写寄存器后状态

Stalker 的指令 callout 在指令执行前获得 context。为了输出 unidbg 风格的写后寄存器值，agent 使用相邻事件补全：

1. 当前指令记录执行前寄存器快照和写寄存器 mask。
2. 下一条指令 callout 的执行前快照等价于上一条指令的执行后状态。
3. `completePreviousInstruction()` 比较两份快照并写入 `registerChanges`。
4. Writer 将变化后的值放在 `=>` 后。

对需要在执行完成后立即停止的终点指令，agent 会插入额外 callout；无法取得写后状态时不会伪造值。

## 数据流与输出

```text
Stalker callout
  -> JavaScript row buffer
  -> send({ type: "trace", items: [...] })
  -> Python on_message
  -> UnidbgTextWriter.write
  -> UTF-8 text file
```

输出示例：

```text
[Test.vmp.exe                     0x0000000000001133] [488b4f08                      ] 0x0000000140001133: "mov rcx, qword ptr [rdi + 8]" (r 0x6d65f8 8) rdi=0x6d65f0 => rcx=0x6d6649
```

`flush` 控制每个 Frida message 的最大行数，不改变最终文本语义。较小批次降低单次消息延迟，较大批次减少 IPC 开销。

## 停止与失败处理

正常停止条件：

- owner thread 执行 inclusive stop RVA。
- `stop-rva=0` 时进程退出。
- 用户向 Python 控制器发送 `Ctrl+C`。

关键失败点：

| 阶段 | 典型原因 | 可见结果 |
| --- | --- | --- |
| 创建目标 | EXE/cwd 无效或权限不足 | `CreateProcessW failed`。 |
| 注入 DLL | 架构不匹配、DLL 路径错误、`DllMain` 返回失败 | `remote LoadLibraryW failed`。 |
| VEH 触发 | 模块/符号错误或触发函数未执行 | hit timeout。 |
| Frida ready | 附加失败、agent 脚本错误或模块未解析 | ready timeout。 |
| 起点 | 模块名/RVA 不匹配或执行流未经过起点 | 0 行或一直等待。 |
| 终点 | RVA 未执行 | 等待至 trace timeout 或用户中断。 |

Launcher 发生交接失败时会设置 ready event，避免目标永久阻塞在 VEH 中。

## 目录结构

```text
frida_instr_trace/
  cli.py                 Python PID 控制器
  unidbg_text.py         唯一文本 renderer
  agent/rva_trace.js     Frida Stalker agent
native/
  veh-dll/               目标内 VEH 与断点组件
  veh-injector/          用户入口与生命周期控制
tests/
  test_unidbg_text.py    文本格式和覆盖写测试
build-native.cmd         两个 native 工程的构建入口
```

## 设计约束

- 当前实现只支持 Windows x64。
- Launcher、DLL、共享结构和目标必须是相同 x64 架构。
- VEH DLL 在 `DllMain` 中创建同步对象、安装 VEH、暂停线程并设置断点；这些操作处于 loader lock 环境，是当前实现的重要约束。修改 DLL 初始化流程时必须重新做端到端启动与退出验证。
- 软件断点会临时修改触发函数首字节，VEH 必须在继续执行前恢复原字节并刷新指令缓存。
- 线程暂停和恢复按线程快照执行；目标在交接期间快速创建或退出线程时可能存在竞态。
- 文本格式面向可读性，不是稳定的二进制交换协议。

## 修改检查清单

修改同步、边界或 agent 行为后至少执行：

```cmd
uv sync --locked
uv run pytest
node --check frida_instr_trace\agent\rva_trace.js
build-native.cmd
```

涉及 VEH、gate 或线程所有权时，还应使用 v3 命令做端到端验证，确认首条为 start RVA、末条为 inclusive stop RVA，并确认目标新控制台能够正常输入和退出。
