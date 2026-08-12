# frida-instr-trace

Windows x64 指令级 RVA 跟踪工具。Native launcher 挂起启动目标、注入 VEH DLL，在触发点与 Frida Stalker 交接，并把 owner thread 的指令记录为开源 unidbg `AssemblyCodeDumper` 风格文本。

详细的组件职责、启动时序、同步协议和 Stalker 数据流见 [工作原理与架构](docs/ARCHITECTURE.md)。

## 特性

- 仅支持 native launcher 启动流程，不提供 Python 直启模式。
- 默认在独立新控制台中挂起启动目标。
- 支持同模块或跨模块的 inclusive 起止 RVA。
- `start-rva=0` 表示起始模块首条观察到的指令；`stop-rva=0` 表示跟踪到进程退出。
- 默认仅记录目标/边界模块；`--target-only 0` 可保留 owner thread 的跨模块执行流。
- 记录机器码、汇编、寄存器读写、内存有效地址及外部函数目标。
- 每次运行截断并重新创建 trace，不支持追加。
- 唯一产物是 UTF-8 unidbg 风格文本。

## 环境

- Windows x64
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Visual Studio 2022 C++ x64 工具链

## 安装与构建

```cmd
uv sync
build-native.cmd
```

构建产物：

```text
native\veh-dll\x64\Release\veh-dll.dll
native\veh-injector\x64\Release\veh-injector.exe
```

## 使用

```cmd
set "FRIDA_TRACE_TRIGGER_MODULE=ucrtbase.dll" && set "FRIDA_TRACE_TRIGGER_SYMBOL=__p___argv" && native\veh-injector\x64\Release\veh-injector.exe --exe "C:\path\to\target.exe" --module "target.exe" --start-rva 0x1000 --end-rva 0x1100 --out ".\traces\target.txt" -- --arg1 value
```

字面量 `--` 后的内容会传给目标程序。`--dll` 和 `--frida` 通常无需指定，launcher 默认使用本仓库的构建产物和 `.venv\Scripts\frida-rva-trace.exe`。

### 参数

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--exe PATH` | 必需 | 要挂起启动的 x64 EXE。 |
| `--module NAME` | EXE 文件名 | 主要跟踪模块。 |
| `--start-module NAME` | `--module` | 起始边界模块。 |
| `--stop-module NAME` | `--module` | 结束边界模块。 |
| `--start-rva RVA` | `0` | Inclusive 起点。 |
| `--end-rva RVA` / `--stop-rva RVA` | `0` | Inclusive 终点。 |
| `--target-only 0\|1` | `1` | 是否只记录目标/边界模块。 |
| `--out PATH` | `traces\native-trace.txt` | 每次重新创建的输出文件。 |
| `--cwd PATH` | EXE 目录 | 目标工作目录。 |
| `--flush COUNT` | `1024` | 每批发送行数；`0` 使用 16384。 |
| `--hit-timeout-ms MS` | `60000` | 等待 VEH 触发超时。 |
| `--ready-timeout-ms MS` | `30000` | 等待 Frida 就绪超时。 |
| `--trace-timeout-ms MS` | `0` | 跟踪超时；`0` 表示无限等待。 |
| `--dll PATH` | 仓库构建产物 | 覆盖 VEH DLL 路径。 |
| `--frida PATH` | 仓库虚拟环境 | 覆盖内部控制器路径。 |

## 输出格式

```text
[Test.vmp.exe                     0x0000000000001133] [488b4f08                      ] 0x0000000140001133: "mov rcx, qword ptr [rdi + 8]" (r 0x6d65f8 8) rdi=0x6d65f0 => rcx=0x6d6649
```

- `(r 地址 大小)`：内存读。
- `(w 地址 大小)`：内存写。
- `(rw 地址 大小)`：内存读写。
- `=>` 后是执行后的写寄存器。
- 外部函数目标追加为 `; module.function`。
- 不记录内存值。

## V3 测试

在仓库根目录的 CMD 中执行：

```cmd
set "FRIDA_TRACE_TRIGGER_MODULE=ucrtbase.dll" && set "FRIDA_TRACE_TRIGGER_SYMBOL=__p___argv" && native\veh-injector\x64\Release\veh-injector.exe --exe "C:\project\vmp\dump\vmp_v3_manxue\Test.vmp.exe" --module "Test.vmp.exe" --start-rva 0x1133 --end-rva 0x113c --out "C:\project\frida-trace\traces\v3-unidbg.txt" --flush 1024 --trace-timeout-ms 0 -- hello
```

## 验证

```cmd
uv run pytest
build-native.cmd
```
