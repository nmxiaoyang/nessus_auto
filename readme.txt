内蒙网络安全
内蒙古网络安全
内蒙古网络安全等级保护
内蒙古网络安全服务
内蒙小杨 

微信号： mtproto 


# 📘 Nessus 自动扫描脚本使用说明

本脚本用于配合 Nessus 扫描器实现月度漏洞扫描任务的自动化处理，包括：

- 读取任务列表（CSV）
- 自动创建并启动主机或 Web 扫描任务
- 等待扫描完成
- 导出 PDF 漏洞报告
- 汇总所有任务漏洞等级至 Excel 表
- 自动删除扫描任务避免重复堆积

---

## 📁 文件结构

nessus_auto_scan.py # 主程序 scan_tasks.csv # 扫描任务列表（用户填写） Nessus_Reports/ # 自动生成的报告目录（含 PDF 和 Excel）



## ✅ 安装依赖

脚本依赖 Python 第三方库：

pip install requests pandas openpyxl
🧾 任务文件格式（scan_tasks.csv）
请使用如下格式填写扫描任务：


任务名称	ip地址
办公OA	192.168.1.1-51
人事管理系统	192.168.2.52
web门户系统	http://192.168.0.2
如果 任务名称 中包含 web 且 ip地址 是 URL（如 http://...），将识别为 Web 扫描，使用 webapp 模板。

其他情况视为主机扫描，使用 basic 模板。

🚀 使用方式
1. 创建并启动扫描任务

python nessus_auto_scan.py scan_tasks.csv
读取 CSV 中的所有任务

自动根据任务名称/目标选择模板

创建并启动扫描

⚠️ 注意：执行后请等待数小时或次日再进行导出操作，以确保所有任务扫描完成。

2. 导出报告 + 汇总漏洞 + 删除任务
python nessus_auto_scan.py
获取 Nessus 中所有扫描任务

自动等待扫描完成

导出 PDF 报告至本地

汇总所有任务的漏洞数量（按等级）

自动删除已完成的扫描任务

输出内容如下：

Nessus_Reports/
└── 20250422/
    ├── 办公OA_漏洞报告.pdf
    ├── 人事管理系统_漏洞报告.pdf
    ├── web门户系统_漏洞报告.pdf
    └── 漏洞汇总.xlsx
⚙️ 配置参数修改
请在脚本顶部配置你自己的 Nessus 连接参数：

NESSUS_URL = "https://your-nessus-ip:8834"
ACCESS_KEY = "你的 access key"
SECRET_KEY = "你的 secret key"
📝 常见问题
如何判断扫描完成？
脚本会循环等待扫描状态变为 completed，才导出报告。

是否支持 IP 范围？
支持，例如 192.168.0.1-20。

是否支持域名或 URL？
支持，只要是带 http:// 或 https:// 就会识别为 Web 扫描。

任务执行失败怎么办？
脚本会打印失败原因，如需自动重试请联系脚本维护者升级。

