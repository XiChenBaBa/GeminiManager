下面是一个美化且完整的 **GitHub README**，使用Markdown格式：

````markdown
# 🚀 Gemini API 管理器

一个用于高效管理 Gemini API 密钥的系统，具备自动轮询、代理支持和实时统计监控等丰富功能，帮助你更好地管理 API 使用和安全性。

---

## ✨ 功能亮点

- 🔄 **自动轮询**：系统自动轮询使用可用的 API 密钥，保障服务持续稳定。
- 🛡️ **自动禁用**：自动检测并禁用无效的 API 密钥，避免重复调用失败。
- 🌐 **代理支持**：支持为每个 API 密钥独立配置代理（兼容 SOCKS5、HTTP 协议）。
- 🔧 **实时管理**：所有配置更改立即生效，无需重启服务，管理更灵活。
- 📊 **统计监控**：实时查看每个 API 密钥的调用统计和成功率，轻松管理 API 健康度。
- 🔍 **完整显示**：鼠标悬停即可查看完整的 API 密钥，操作便捷。
- 🔐 **安全认证**：管理面板采用密码认证保护，会话有效期 1 小时，确保管理安全。

---

## 📌 快速开始

```bash
# 克隆仓库
git clone https://github.com/XiChenBaBa/GeminiManager.git

# 进入项目目录
cd GeminiManager

# 安装依赖
pip3 install -r requirements.txt

# 运行服务
python3 main.py
````

---

## 🎯 使用场景

* ✅ API 密钥批量管理与优化
* ✅ 高并发环境的 API 调用监控
* ✅ 企业级 API 使用安全管理与监控

---

## 📸 界面预览

*(建议在此插入系统截图或GIF，提升用户体验与直观感受)*

---

## ⚙️ 技术栈

* Python
* Flask
* Requests
* Proxy 支持（HTTP/SOCKS5）

---

## 🤝 贡献

欢迎提交 Issues 或 Pull Requests 来帮助完善该项目。

---

## 📄 开源许可

本项目基于 [MIT License](LICENSE) 开源。

---

> ⭐️ 如果觉得本项目对你有所帮助，欢迎给一个 Star 以示支持，谢谢！
