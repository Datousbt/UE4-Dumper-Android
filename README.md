# UE4 Function Address Finder - Android Edition

UE4 引擎函数地址扫描器 —— Android/Linux 移植版。

从原始项目 [UE4-Function-Address-Finder](https://github.com/Datousbt/UE4-Function-Address-Finder.git) (Windows/MSVC) 移植，支持在 **Android 手机** 和 **Linux** 上直接扫描 UE4 游戏进程内存，定位关键引擎函数地址。

## 支持的架构

| 架构 | 状态 | 说明 |
|---|---|---|
| ARM64 (AArch64) | ✅ 主要目标 | 绝大多数 Android 手机 |
| x86_64 | ✅ 支持 | Android 模拟器 / Linux PC |

## 功能

自动扫描并定位以下 UE4 引擎内部地址：

| 符号 | 用途 |
|---|---|
| `GNames` / `FNamePool` | 名字表 (UE4 反射核心) |
| `GObjects` | 全局 UObject 数组 |
| `GWorld` | 当前 UWorld 指针 |
| `ProcessEvent` | UFunction 调用入口 (Hook 必备) |
| `StaticLoadObject` | 运行时资源加载 |
| `SpawnActorFTransform` | 带 Transform 的 Actor 生成 |
| `CallFunctionByNameWithArguments` | 按名字调用 UFunction |
| `GameStateInit` | GameState 初始化 Hook 点 |
| `BeginPlay` | Actor BeginPlay Hook 点 |

输出格式兼容主流 UE4 SDK 生成器。

## 快速开始

### 方案 A: 在手机上用 Termux 编译（推荐）

```bash
# 1. 安装 Termux (https://termux.com) 并配置
pkg update && pkg upgrade
pkg install clang cmake make git

# 2. 克隆仓库
git clone https://github.com/Datousbt/UE4-Dumper-Android.git
cd UE4-Dumper-Android

# 3. 编译
./build.sh local

# 4. 使用 (需要 root)
su -c './build/arm64-v8a/ue4_dumper --list'
su -c './build/arm64-v8a/ue4_dumper <PID> --ue4-version 426'
```

### 方案 B: 用 Android NDK 交叉编译

```bash
# 设置 NDK 路径
export ANDROID_NDK_HOME=/path/to/android-ndk

# 编译 ARM64
./build.sh arm64

# 或者编译所有架构
./build.sh all

# 推送到手机
adb push build/arm64-v8a/ue4_dumper /data/local/tmp/
adb shell su -c 'chmod +x /data/local/tmp/ue4_dumper'
```

### 方案 C: 在 Linux PC 上编译

```bash
./build.sh local
# 输出: build/x86_64/ue4_dumper
```

## 使用说明

```bash
# 需要 root 权限！
su

# 列出正在运行的 UE4 游戏进程
./ue4_dumper --list

# 扫描指定进程 (自动检测引擎版本)
./ue4_dumper <PID>

# 手动指定引擎版本 (推荐)
./ue4_dumper <PID> --ue4-version 426    # UE 4.26
./ue4_dumper <PID> --ue4-version 425    # UE 4.25

# 自定义输出文件名
./ue4_dumper <PID> --ue4-version 426 --output MyGame
```

### 引擎版本号对照

| UE4 版本 | --ue4-version 参数 |
|---|---|
| 4.27 | 427 |
| 4.26 | 426 |
| 4.25 | 425 |
| 4.24 | 424 |
| 4.23 | 423 |
| 4.22 | 422 |
| 4.21 | 421 |

## 输出示例

```
[*] Target: libUE4.so (base=0x71a0000000, size=0x5c00000)
[*] Searching for GNames/FNamePool...
[+] GNames: 0xb3e82a0
[*] StaticLoadObject: 0x559e120
[*] SpawnActorFTransform: 0x5642ab0
[+] Profile saved as MyGame.profile
```

生成的 `.profile` 文件可直接导入 SDK 生成工具。

## 工作原理

1. **进程附加** — 通过 `/proc/<pid>/mem` 和 `process_vm_readv` 读取目标进程内存
2. **签名扫描** — 使用 KMP 算法 + 通配符 (0xFF) 进行 AOB 模式匹配
3. **字符串引用定位** — 通过 UE4 错误消息字符串间接定位目标函数
4. **地址解析** — 计算 RIP-relative (x86_64) 或 ADRP-relative (ARM64) 偏移
5. **结构验证** — 通过已知的 UE4 结构布局验证找到的地址
6. **Profile 输出** — 生成 SDK 生成器兼容的 INI 格式文件

## ARM64 与 x86_64 差异

原始项目针对 Windows x86_64 PE 可执行文件。Android 移植的关键变化：

| 原始 (Windows/x86_64) | 移植 (Android/ARM64) |
|---|---|
| `ReadProcessMemory` | `process_vm_readv` |
| `VirtualQueryEx` | 解析 `/proc/<pid>/maps` |
| PE 格式解析 | ELF 格式解析 |
| LEA rip-relative 寻址 | ADRP + ADD 寻址 |
| x86 函数序言 (`push rbp`) | ARM64 函数序言 (`STP X29,X30`) |
| x86 CALL (`0xE8`) | ARM64 BL (`0x94...`) |

**注意**: ARM64 AOB 特征码仍在完善中。欢迎贡献 ARM64 签名！

## 前置条件

- **Root 权限**: 读取其他进程内存需要 root
- **SELinux**: 可能需要设为 Permissive 模式 (`setenforce 0`)
- **UE4 游戏**: 必须正在运行

## 与原始项目的出处

原始项目: [UE4-Function-Address-Finder](https://github.com/Datousbt/UE4-Function-Address-Finder.git)
作者: PotatoPie (Patrick)
许可: 与原始项目保持一致

## License

MIT License - 详见原始项目
