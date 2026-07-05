# erofs-rs 文档

本目录包含 `erofs-rs` 的设计、开发与使用文档。

## 文档索引

1. [项目起源与设计理念](01-origin-and-design.md) — 为什么创建这个项目、项目定位、核心设计原则。
2. [Fuzzing Architecture](02-fuzzing-architecture.md) — fuzzing 分层、campaign 数据流、artifact 合约、CI 职责和扩展规则。
3. [Corpus and Artifact Formats](03-corpus-format.md) — seed、coverage corpus、fuzz artifact 和 finding bundle 的格式与导入规则。

## 计划中的文档

- `usage.md` — 各子命令详细用法与示例。
- `testing.md` — 测试策略、fixtures 说明、CI 流程。
- `qemu-environment.md` — Makefile QEMU 环境详解。
- `contributing.md` — 贡献指南、代码风格、提交规范。
