# 贡献指南

感谢您考虑为 GoWAF 项目做出贡献！

## 🤝 如何贡献

### 报告 Bug

如果您发现了 bug，请通过 [GitHub Issues](https://github.com/yourusername/gowaf/issues) 提交报告。提交时请包含：

- 详细的 bug 描述
- 复现步骤
- 预期行为
- 实际行为
- 系统环境信息（操作系统、Go版本等）
- 相关日志或截图

### 提出新功能

如果您有新功能的想法，欢迎提交 Issue 讨论。请包含：

- 功能描述
- 使用场景
- 可能的实现方案

### 提交代码

1. **Fork 仓库**
   ```bash
   git clone https://github.com/yourusername/gowaf.git
   ```

2. **创建特性分支**
   ```bash
   git checkout -b feature/AmazingFeature
   ```

3. **进行开发**
   - 遵循 Go 代码规范
   - 添加必要的测试
   - 更新相关文档

4. **提交更改**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```

5. **推送到分支**
   ```bash
   git push origin feature/AmazingFeature
   ```

6. **提交 Pull Request**

## 📝 代码规范

### Go 代码规范

- 遵循 [Effective Go](https://golang.org/doc/effective_go) 指南
- 使用 `gofmt` 格式化代码
- 添加必要的注释和文档
- 保持函数简洁，单一职责

### 提交信息规范

提交信息应清晰描述更改内容：

- `feat: 添加新功能`
- `fix: 修复bug`
- `docs: 更新文档`
- `style: 代码格式调整`
- `refactor: 重构代码`
- `test: 添加测试`
- `chore: 构建或辅助工具变动`

### 测试要求

- 新功能必须添加测试
- Bug 修复应包含回归测试
- 确保所有测试通过
- 保持合理的测试覆盖率

## 🔍 代码审查

所有 Pull Request 都需要经过代码审查：

- 代码质量
- 测试覆盖
- 文档完整性
- 性能影响
- 安全性考虑

## 📄 许可证

通过贡献代码，您同意您的代码将采用 MIT 许可证授权。
