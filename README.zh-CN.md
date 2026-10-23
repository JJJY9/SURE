# SURE

**Software Understanding & Reality Evaluation（软件理解与现实核查）**

> **AI 说"做完了"。用 SURE 验证一下。**

[English](README.md) · [中文](README.zh-CN.md)

SURE 是一个本地优先的检查工具，专门检查用 AI 编程工具写出来的软件，用大白话告诉你这个项目到底行不行。它给出的每个结论都有证据；说不准的，就直说"无法确认"。

它回答三个问题：

1. **这个项目真的能跑吗？**
2. **有没有明显坏的、不安全的、造假的、没做完的部分？**
3. **AI 说"我完成了"，能证实吗？**

发现真问题时，SURE 会说清后果，生成一份有边界的修复契约，你可以把它交回给你的 AI 编程工具，修完之后再复查。**在这个项目里，误报"没问题"比报错更严重。**

SURE 不取代你正在用的工具。用 Claude Code 的继续用 Claude Code，用 Cursor 的继续用 Cursor，用 Codex 的继续用 Codex。

## 在 Windows 上安装

**目前还没有可下载的发布包。** SURE 目前是开发者预览版，安装包要从本仓库自行构建。
如果机器上没有下面的工具链，这就是原因，不是你做错了什么。

构建的机器上需要两样东西：

- **Rust**——装 [rustup](https://rustup.rs) 即可；仓库里的 `rust-toolchain.toml` 固定了版本，rustup 会自动装对。
- **Visual Studio Build Tools**，勾选"使用 C++ 的桌面开发"工作负荷。

然后在本仓库根目录、PowerShell 里：

```powershell
# 1. 发布门禁——SURE 自己的验收测试，要跑几分钟
cargo test -p sure-core --test acceptance_report_runner

# 2. 构建并打包，也要几分钟
& .\scripts\Build-Release.ps1 -Phase All

# 3. 安装到当前用户。不需要管理员，不改 PATH
& .\scripts\Install-Sure.ps1 -Archive .\target\tmp\release\sure-0.1.3-x86_64-pc-windows-msvc.zip

# 4. 验证装好了
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" version
```

程序装在 `%LOCALAPPDATA%\SURE\bin\sure.exe`。以后想卸载：`& .\scripts\Uninstall-Sure.ps1`——它不会删 `sure.db`（你的检查历史）。

完整步骤在 `docs/development/QUICKSTART_WINDOWS.md`；安装器的全部参数在 `docs/development/INSTALL_WINDOWS.md`。

## 在 macOS 和 Linux 上安装

从源码构建：

```sh
cargo install --path crates/sure-cli   # 把 sure 装进 ~/.cargo/bin
```

Unix 的启动脚本默认就在这个位置找它。Rust 核心是可移植的，两个平台都有 CI 覆盖；`docs/development/MACOS.md` 和 `docs/development/LINUX.md` 写清了各自的支持边界。

## 使用

先检查 SURE 自己在这台机器上装得对不对：

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" doctor
```

检查一个项目。路径必须是绝对路径：

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" check "C:\demo\hello"
```

### 一次运行长什么样

下面是一次真实的 `sure check` 运行，被检查的项目只有一个 `package.json` 和一个 JavaScript 文件——这是 SURE 0.1.3 的输出，按小节裁剪过。项目路径替换成了 `C:\demo\hello`，标 `...` 的行是省略的地方：

```text
SURE checked C:\demo\hello.

Not enough could be checked to say whether this is ready.
This project is not ready to hand off.
...
No open findings.

What the run did, stage by stage
  1/12. Find the project's parts: node (level B); all of it was read. Support reaches level B.
  ...
  8/12. Ask a model to assess the project: No analysis provider is configured, so SURE assessed nothing with a model. ... (NOT CHECKED)
  9/12. Check what was claimed against the evidence: SURE has no recorded history for this machine, so there are no agent claims to check against evidence. (NOT CHECKED)
  ...

2 of the 12 stages did not run, and each is marked NOT CHECKED above. A run with
a stage that did not run is never reported as clean.

SURE exited with status 1. That is what it returns when it checked the project
and did not find it clean — not 3, which would mean this build cannot check a
project at all.
```

退出码就是答案：

| 退出码 | 含义 |
| --- | --- |
| `0` | 干净——跑了的检查全部通过，没有跳过任何一项 |
| `1` | 查了，不干净——有发现，或者能查的不够、没法判定干净 |
| `5` | 这次运行没完成（路径不对、项目读不了） |
| `2` | 命令行本身写错了 |

**前几次跑大概率得到 `1`，这是正常的。** 默认没有配置 AI 模型时，SURE 只跑确定性检查，"模型评估"这一步会标记为"未检查"；而有任何一步没跑的报告，永远不会被判为干净。这是工具在诚实，不是你的项目坏了。第 9 步要靠下面的插件提供的会话记录，所以没用过 SURE 的机器会有两步被标记。

其他常用命令：

- `sure config set execution.mode host_confirmed`——允许 SURE 运行项目自己的命令（测试、构建），而不只是读文件
- `sure repair`——把发现的问题变成一份有边界的修复契约，交给 AI 工具去修
- `sure recheck`——修完后复查，并和上次对比
- `sure history`——查看（或删除）SURE 在这台机器上的记录
- 任何命令加 `--format json`，输出一行一个 JSON 对象，给脚本读

第一次检查不会在你机器上留下任何文件：只有已经存在历史记录时 SURE 才会打开它。

## 接入你的 AI 编程工具

SURE 还可以（只在你同意后）记录编程会话，把 AI 的"做完了"和实际发生的事对照。这需要安装对应工具的插件：

```powershell
# Claude Code——把插件复制到 %LOCALAPPDATA%\claude-plugins\sure
& .\integrations\claude-code\scripts\install.ps1 -ForceCopy
```

把插件加载进 Claude Code 是 Claude Code 自己的操作步骤，`integrations/claude-code/README.md` 里有说明。Cursor 和 Codex 的包结构相同，见 `docs/integrations/INSTALLATION_MATRIX.md`。Copilot 的包目前只是模板，装不了。

不装插件也能用：命令行照常检查项目，只是"声明核对"部分会诚实地说"无法确认"——这是答案，不是缺功能。

## 文件放在哪

Windows 上是 `%LOCALAPPDATA%\SURE\`——程序和 `sure.db`（证据历史）都在这里。SURE 是本地优先的：一切留在你的机器上，不往任何地方传数据。

## 更多

- `ROADMAP.md`——项目到哪了、接下来做什么
- `FINAL_REPORT.md`——这个 v0.1 是什么、不是什么，带测量
- `docs/`——架构、安全、集成、开发文档
- `START_HERE.md`——想参与开发 SURE 本身，从这里开始

## 许可证

Apache-2.0，见 `LICENSE`。
