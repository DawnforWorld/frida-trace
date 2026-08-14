# 排障指南

本文按 launcher 的运行阶段定位问题。先看控制台最后一条日志和进程返回码，再对照对应阶段检查。

## 快速检查

1. 确认在仓库根目录执行命令。
2. 执行 `uv sync --locked`，确认 `.venv\Scripts\frida-rva-trace.exe` 存在。
3. 执行 `build-native.cmd`，确认 native 构建产物存在。
4. 确认目标、launcher、VEH DLL 都是 x64。
5. 确认 `--exe`、`--cwd`、`--dll`、`--frida` 指向的路径真实存在。
6. 确认 `--trigger-module` 在 DLL 注入时已经加载，`--trigger-symbol` 或 `--trigger-rva` 可解析；使用 `--trigger-rva` 时必须同时指定 `--trigger-module`。
7. 确认 `--module`、`--start-module`、`--stop-module` 与 Frida 看到的模块名或完整路径匹配。

## 返回码

| 返回码 | 阶段 | 常见原因 |
| --- | --- | --- |
| `2` | 参数或路径校验 | 缺少 `--exe`，参数值非法，EXE/DLL/Frida/cwd 不存在。 |
| `3` | 创建目标或同步对象 | `CreateProcessW` 失败、权限不足、工作目录无效。 |
| `4` | DLL 注入 | 架构不匹配、DLL 路径错误、`DllMain` 返回失败、触发点无法设置。 |
| `5` | 恢复主线程 | `ResumeThread` 失败。 |
| `6` | 等待 VEH 命中 | 触发模块/符号/RVA 错误，或目标没有执行到触发点。 |
| `7` | 读取共享状态 | DLL 已命中但共享映射不可读或协议版本不匹配。 |
| `9` | 启动 Python 控制器 | `.venv\Scripts\frida-rva-trace.exe` 不存在或无法启动。 |
| `10` | 等待 Frida ready | Frida attach 失败、agent 脚本错误、目标模块尚未解析。 |
| `11` | trace 超时 | `--trace-timeout-ms` 到期但 stop RVA 未执行或控制器未退出。 |

Python 控制器自身返回码：

| 返回码 | 含义 |
| --- | --- |
| `0` | 正常退出。 |
| `1` | 未分类异常。 |
| `2` | CLI 参数错误。 |
| `3` | Frida 找不到目标进程。 |
| `4` | Frida transport 错误。 |

## 常见问题

### `invalid EXE, DLL, Frida executable, or cwd path`

检查 `--exe` 和 `--cwd`。如果没有显式传 `--dll` 或 `--frida`，launcher 默认从仓库根目录推导：

```text
native\veh-dll\x64\Release\veh-dll.dll
.venv\Scripts\frida-rva-trace.exe
```

缺少这些文件时，重新执行：

```cmd
uv sync --locked
build-native.cmd
```

### `remote LoadLibraryW failed`

优先检查三件事：

- 目标进程、`veh-dll.dll` 和 launcher 是否都是 x64。
- `--trigger-module` 是否在 DLL 注入时已经加载。
- `--trigger-rva` 是否配合 `--trigger-module` 使用并位于模块范围内，或 `--trigger-symbol` 是否是有效导出符号。

如果使用默认触发点失败，可以改成目标模块内较早执行的 RVA：

```cmd
native\veh-injector\x64\Release\veh-injector.exe --exe "C:\path\to\target.exe" --module "target.exe" --start-rva 0x1000 --end-rva 0x1100 --trigger-module "target.exe" --trigger-rva 0x1000 --out ".\traces\target.txt"
```

### `breakpoint event not observed`

VEH DLL 已注入，但目标没有在 `--hit-timeout-ms` 内命中触发点。检查触发函数是否会在当前输入参数下执行。必要时提高 `--hit-timeout-ms`，或换成更确定的触发点。

### `Frida did not become ready`

说明 Frida 控制器没有成功完成 attach 和 agent 初始化。常见原因：

- Frida 运行环境不可用或权限不足。
- `--module`、`--start-module`、`--stop-module` 名称不匹配。
- JavaScript agent 语法错误或运行时异常。

修改 agent 后先执行：

```cmd
node --check frida_instr_trace\agent\rva_trace.js
```

### 生成了空 trace

控制器能运行，但 owner thread 没有经过 start RVA。检查：

- `--start-rva` 是否是模块 RVA，不是绝对 VA。
- `--start-module` 是否正确。
- 触发点是否过晚，导致目标已经越过 start RVA。
- 默认 `--target-only 1` 是否过滤了你需要观察的跨模块流，必要时尝试 `--target-only 0`。

### 一直等待不退出

`--end-rva 0` 表示等目标进程退出；非 0 时只有 owner thread 执行到 inclusive stop RVA 才会停止。调试阶段建议设置有限超时：

```cmd
--trace-timeout-ms 30000
```

### trace 缺少外部模块指令

默认 `--target-only 1` 只记录目标/边界模块。需要保留 owner thread 的跨模块执行流时设置：

```cmd
--target-only 0
```

## 验证命令

```cmd
uv run pytest
node --check frida_instr_trace\agent\rva_trace.js
build-native.cmd
```

涉及 VEH、gate 或线程交接的改动，还应使用真实目标做端到端验证，确认命中触发点、开始记录、到达 stop RVA 并生成非空 trace。
