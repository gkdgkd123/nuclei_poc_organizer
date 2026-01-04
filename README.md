# Nuclei POC Organizer

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Nuclei](https://img.shields.io/badge/tool-Nuclei-orange)

一个专为安全研究人员打造的高级 Nuclei POC 整理工具。支持智能去重、鲁棒分类、WordPress 专区分离以及同名文件冲突智能处理。

## ✨ 主要功能

* **🧠 智能去重 (Intelligent Deduplication)**
    * **MD5 精确去重**：秒杀完全一致的文件。
    * **逻辑特征去重 (Jaccard)**：基于特征指纹识别写法不同但逻辑相同的 POC（如 `raw` vs `http` 写法的同一漏洞）。
* **🛡️ 鲁棒分类 (Robust Classification)**
    * 自动解析 YAML 中的 `severity` 字段进行分类。
    * **双重解析引擎**：当标准 YAML 解析失败时，自动切换到正则匹配模式，最大程度挽救格式不标准的 POC。
* **📂 结构化整理**
    * **WordPress 专区**：自动识别 WP 相关 POC 并独立归档。
    * 按等级分类：`critical`, `high`, `medium`, `low`, `info`。
* **⚖️ 智能冲突处理**
    * 当遇到同名文件时，自动保留**体积最大**的版本（通常包含更完整的描述或 Payload）。
    * **零冗余**：绝不生成 `_1.yaml` 等垃圾后缀。

## 🚀 快速开始

### 安装依赖

脚本仅依赖 `PyYAML`：

```bash
pip install PyYAML
```

### 使用方法

```bash
python3 nuclei_organizer.py -i <输入目录> -o <输出目录>
```

### 示例

假设你有一堆杂乱的 POC 在 `raw_pocs` 目录下：

```bash
python3 nuclei_organizer.py -i ./raw_pocs -o ./clean_pocs
```

运行结束后，`clean_pocs` 目录结构将变得非常整洁：

```text
clean_pocs/
├── critical/
├── high/
├── ...
└── wordpress/          # WordPress 独立专区
    ├── critical/
    └── high/
```

## 🛠️ 工作原理

1.  **扫描与分组**：遍历所有文件，首先根据“规范化文件名”进行聚合。
2.  **特征提取**：读取文件内容，提取关键路径、参数和匹配词作为特征指纹。
3.  **相似度计算**：计算组内文件的 Jaccard 相似度，过滤掉逻辑重复的“影子文件”。
4.  **优胜劣汰**：在同名冲突或逻辑重复中，始终保留内容最丰富（体积最大）的文件。
5.  **分类归档**：双重解析获取等级，识别 WP 特征，移动到最终目录。

## 🤝 贡献

欢迎提交 Issue 或 Pull Request 来改进这个工具！

## 📄 许可证

本项目基于 [MIT License](LICENSE) 开源。
