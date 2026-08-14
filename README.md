# frida-instr-trace

Windows x64 指令级 RVA 跟踪工具。Native launcher 挂起启动目标、注入 VEH DLL，在触发点与 Frida Stalker 交接，并把 owner thread 的指令记录为开源 unidbg `AssemblyCodeDumper` 风格文本。

## 文档索引

- [工作原理与架构](docs/ARCHITECTURE.md)：组件边界、启动时序、同步协议和 Stalker 数据流。
- [排障指南](docs/TROUBLESHOOTING.md)：常见失败阶段、返回码和定位步骤。

## 能力边界

- 只支持 Windows x64 目标、x64 launcher、x64 VEH DLL。
- 用户入口是 `native\veh-injector\x64\Release\veh-injector.exe`，Python `frida-rva-trace` 是 launcher 启动的内部控制器。
- 默认在独立新控制台中挂起启动目标，然后注入 VEH DLL。
- 支持同模块或跨模块的 inclusive 起止 RVA。
- `start-rva=0` 表示起始模块首条观察到的指令；`stop-rva=0` 表示跟踪到进程退出。
- 默认只记录目标/边界模块；`--target-only 0` 可保留 owner thread 的跨模块执行流。
- 记录机器码、汇编、寄存器读写、内存有效地址及外部函数目标，不读取内存值。
- 每次运行都会截断并重新创建输出文件，不支持追加。
- 唯一输出格式是 UTF-8 unidbg 风格文本。

## 环境要求

- Windows x64
- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Visual Studio 2022 C++ x64 工具链，包含 MSBuild
- 本机可用的 Frida runtime，依赖由 `uv sync` 安装

## 安装与构建

在仓库根目录执行：

```cmd
uv sync --locked
build-native.cmd
```

构建产物：

```text
native\veh-dll\x64\Release\veh-dll.dll
native\veh-injector\x64\Release\veh-injector.exe
```

`build-native.cmd` 会通过 Visual Studio Installer 的 `vswhere.exe` 查找 x64 MSBuild，并分别构建 VEH DLL 和 launcher。

## 快速使用

```cmd
native\veh-injector\x64\Release\veh-injector.exe --exe "C:\path\to\target.exe" --module "target.exe" --start-rva 0x1000 --end-rva 0x1100 --trigger-module "ucrtbase.dll" --trigger-symbol "__p___argv" --out ".\traces\target.txt" -- --arg1 value
```

命令分成两段：

- `veh-injector.exe` 前半段参数控制启动、注入、Frida 交接和 trace 范围。
- 字面量 `--` 后的内容原样传给目标程序。

通常不需要显式指定 `--dll` 和 `--frida`。launcher 会默认使用本仓库的：

```text
native\veh-dll\x64\Release\veh-dll.dll
.venv\Scripts\frida-rva-trace.exe
```

## 参数

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `--exe PATH` | 必需 | 要挂起启动的 x64 EXE。 |
| `--module NAME` | EXE 文件名 | 主要跟踪模块。可以是模块名，也可以是完整路径。 |
| `--start-module NAME` | `--module` | 起始边界模块。 |
| `--stop-module NAME` | `--module` | 结束边界模块。 |
| `--start-rva RVA` | `0` | Inclusive 起点。支持十进制或 `0x` 十六进制。 |
| `--end-rva RVA` / `--stop-rva RVA` | `0` | Inclusive 终点。`0` 表示等待目标进程退出。 |
| `--target-only 0\|1` | `1` | 是否只记录目标/边界模块。 |
| `--out PATH` | `traces\native-trace.txt` | 每次重新创建的输出文件。 |
| `--cwd PATH` | EXE 所在目录 | 目标工作目录。 |
| `--flush COUNT` | `1024` | 每批发送行数；`0` 使用 16384。 |
| `--hit-timeout-ms MS` | `60000` | 等待 VEH 触发超时。 |
| `--ready-timeout-ms MS` | `30000` | 等待 Frida 就绪超时。 |
| `--trace-timeout-ms MS` | `0` | 跟踪超时；`0` 表示无限等待。 |
| `--dll PATH` | 仓库构建产物 | 覆盖 VEH DLL 路径。 |
| `--frida PATH` | 仓库虚拟环境 | 覆盖内部控制器路径。 |
| `--trigger-module NAME` | `ucrtbase.dll` | VEH 触发模块。 |
| `--trigger-symbol NAME` | `__p___argv` | VEH 触发导出符号。 |
| `--trigger-rva RVA` | 未设置 | VEH 触发模块内 RVA；需同时指定 `--trigger-module`，设置后优先于符号。 |

## 触发点选择

VEH DLL 需要在 Frida 附加前设置一个软件断点，命中后把 owner thread 和触发地址交给 Frida agent。默认触发点是 `ucrtbase.dll!__p___argv`，适合很多普通控制台程序；如果目标在该函数前已经执行了关键代码，或没有走到该符号，需要换触发点。

推荐选择：

- 已经在 DLL 注入时加载的模块。
- 会在目标关键逻辑前执行的导出函数或模块内 RVA。
- 足够早，但不会早到目标模块尚未加载完成的位置。

示例：按模块内 RVA 触发。

```cmd
native\veh-injector\x64\Release\veh-injector.exe --exe "C:\path\to\target.exe" --module "target.exe" --start-rva 0x1133 --end-rva 0x113c --trigger-module "target.exe" --trigger-rva 0x1000 --out ".\traces\target.txt"
```

`--trigger-rva` 必须和 `--trigger-module` 一起使用。`--trigger-*` 参数由 launcher 转换成目标进程环境变量 `FRIDA_TRACE_TRIGGER_MODULE`、`FRIDA_TRACE_TRIGGER_SYMBOL` 和 `FRIDA_TRACE_TRIGGER_RVA`，一般不需要手动设置这些环境变量。

## 输出格式

示例行：

```text
[Test.vmp.exe                     0x0000000000001133] [488b4f08                      ] 0x0000000140001133: "mov rcx, qword ptr [rdi + 8]" (r 0x6d65f8 8) rdi=0x6d65f0 => rcx=0x6d6649
```

- 方括号第一段：模块名和模块内 RVA。
- 方括号第二段：指令机器码。
- 引号内：Frida 解析出的汇编文本。
- `(r 地址 大小)`：内存读。
- `(w 地址 大小)`：内存写。
- `(rw 地址 大小)`：内存读写。
- `=>` 后：执行后的写寄存器值。
- `; module.function`：离开当前模块的外部函数目标。

输出不包含内存值，也不是稳定的二进制交换协议。

## 示例

V3 测试命令示例，需在仓库根目录的 CMD 中执行，并按本机目标路径调整 `--exe`：

```cmd
native\veh-injector\x64\Release\veh-injector.exe --exe "C:\project\vmp\dump\vmp_v3_manxue\Test.vmp.exe" --module "Test.vmp.exe" --start-rva 0x1133 --end-rva 0x113c --trigger-module "ucrtbase.dll" --trigger-symbol "__p___argv" --out "C:\project\frida-trace\traces\v3-unidbg.txt" --flush 1024 --trace-timeout-ms 0 -- hello
```

期望现象：launcher 创建新控制台目标，命中 VEH 断点后启动 Frida 控制器，最终在 `--out` 路径生成 trace 文本。

## 开发与验证

常规验证：

```cmd
uv sync --locked
uv run pytest
build-native.cmd
```

修改 JavaScript agent 后额外执行：

```cmd
node --check frida_instr_trace\agent\rva_trace.js
```

修改同步、VEH、gate、线程所有权或边界语义后，还需要做端到端 trace 验证：确认首条记录符合 start RVA，末条记录包含 inclusive stop RVA，并确认目标新控制台能够正常输入和退出。
