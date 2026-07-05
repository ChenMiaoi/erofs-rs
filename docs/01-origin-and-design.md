# 项目起源与设计理念

## 起源

`erofs-rs` 源自 **Google Summer of Code 2026** 项目：

- **项目页面**: <https://summerofcode.withgoogle.com/programs/2026/projects/XxkEzKgA>
- **目标**: 针对 Linux 内核中的 EROFS 文件系统，建立一套面向安全研究的模糊测试（fuzzing）与畸形镜像注入工具链，帮助在用户命名空间挂载场景下发现潜在的解析漏洞。

EROFS（Enhanced Read-Only File System）是 Linux 内核中广泛使用的只读文件系统，具有压缩、去重、紧凑元数据等特性。由于镜像数据完全来自用户空间（尤其是容器、固件、可信执行环境等场景），恶意构造的 EROFS 镜像可能成为内核攻击面。因此，需要系统化的工具来生成、变异、分类和回归测试这些镜像。

## 项目定位

`erofs-rs` 是一个独立的 Rust 仓库，提供：

- 可复用的 EROFS 镜像解析与操作库。
- 面向安全研究的 CLI 工具集：注入、变异、语料管理、模糊测试、镜像信息查看。
- 与 `erofs-utils` 及上游 Linux 内核配合的测试基础设施。

## 设计理念

### 1. Library + CLI 一体化

`erofs-rs` 不是一个单纯的命令行工具，而是：

- **库（Library）**：`src/lib.rs` 提供 EROFS 解析、变异、校验 API。
- **CLI**：`src/main.rs` 通过子命令将这些能力暴露给终端用户。

这种结构的好处是：

- 单元测试和集成测试可以直接调用库函数。
- 后续可以在此基础上构建更高级的 fuzzer、web 服务或 IDE 插件。
- 核心逻辑与界面解耦，便于长期演进。

### 2. 与 EROFS 规范及工具链语义一致

核心实现严格对照 EROFS 内核实现与 `erofs-utils` 的行为：

- CRC-32C（Castagnoli）算法与 `erofs_crc32c` 保持一致。
- inode/dirent 定位启发式规则遵循 EROFS 元数据布局。
- `fsck.erofs` 结果分类逻辑覆盖常见的接受、校验和拒绝路径。
- superblock、inode、dirent 的字段定义与 EROFS 头文件一致。

### 3. 模块化 CLI

每个功能对应一个独立的子命令：

| 子命令 | 能力 |
|---|---|
| `inject` | 精确字段或原始偏移注入，用于构造确定性畸形镜像 |
| `mutate` | 结构化单字段变异，批量生成测试用例并调用 fsck 分类 |
| `corpus` | 语料去重、分类、生成报告 |
| `fuzz` | 基于变异的快速模糊测试，随机组合多种变异策略 |
| `oracle` | 对比 Rust parser、fsck.erofs 和可选 dump.erofs 的 userspace oracle 结果 |
| `info` | 镜像元数据查看与 checksum 重算 |

每个模块职责单一，便于单独维护、测试和扩展。

### 4. 安全与可观测性

- **可重复**：每次注入/变异都会生成 manifest，记录输入 SHA-256、字段、旧值、新值和分类结果。
- **可审查**：`info` 命令可以清晰查看 superblock、inode、dirent 结构，方便人工确认变异是否符合预期。
- **可对比**：`oracle` 命令将 Rust parser 与 userspace 工具结果放在同一份报告中，便于发现 parser/tool disagreement。
- **最小侵入**：核心库不依赖外部二进制；只有 `fsck` 模块和 `fuzz` / `mutate` 命令需要 `fsck.erofs`。

### 5. 面向未来的扩展

- 当前 `fuzz` 命令实现的是基于变异的快速 fuzzer；`fuzz/` 目录提供
  Rust 库自身的初始 `cargo-fuzz`/libFuzzer targets，后续仍可以继续扩展
  coverage-guided corpus merge、minimization 和更多格式特性 target。
- `scripts/generate-seed-matrix.sh` 用 mkfs.erofs 生成 block size、
  compression、xattr、POSIX ACL、large directory、special file、socket、
  device node 和 chunked layout 种子矩阵，
  并为每个 seed 记录 manifest。
- `vendor/erofs-utils` 和 `vendor/linux` 以 `--depth=1` submodule 形式纳入，方便与上游同步并构建内核 replay 环境。
- 未来将逐步覆盖压缩布局、xattr、chunk-based 文件等更复杂的 EROFS 特性。

## 设计目标

1. **正确性**：严格遵循 EROFS 格式规范，并与 `erofs-utils` 行为对齐。
2. **性能**：模糊测试与批量变异能够高效执行，支持大规模语料生成。
3. **可维护性**：清晰的模块边界、完整的测试覆盖、规范的 Rust 代码风格。
4. **可扩展性**：库 API 稳定，CLI 子命令易于新增策略和字段。
5. **社区友好**：提供中文与英文文档、示例命令，降低 EROFS 安全研究的参与门槛。

## 相关链接

- GSoC 2026 项目: <https://summerofcode.withgoogle.com/programs/2026/projects/XxkEzKgA>
- EROFS 官方文档: <https://erofs.docs.kernel.org/>
- `erofs-utils`: <https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git>
- Linux 内核: <https://github.com/torvalds/linux.git>
