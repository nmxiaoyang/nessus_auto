import os
import sys
import time
import requests
import pandas as pd
from datetime import datetime
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# === Nessus 配置 ===
NESSUS_URL = "https://你的 nessus 地址:8834"
ACCESS_KEY = "你的 access key"
SECRET_KEY = "你的 secret key"
BASE_DIR = "Nessus_Reports"

urllib3.disable_warnings(InsecureRequestWarning)

session = requests.Session()
session.headers.update({
    "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
    "Accept": "application/json"
})
session.verify = False

def create_report_dir():
    today = datetime.now().strftime("%Y%m%d")
    path = os.path.join(BASE_DIR, today)
    os.makedirs(path, exist_ok=True)
    return path

def safe_filename(name):
    return ''.join(c if c.isalnum() or c in (' ', '_', '-', '.') else '_' for c in name).strip()

def choose_template(task_name, target):
    if "web" in task_name.lower() and target.lower().startswith("http"):
        return "webapp"
    return "basic"

def create_scan(name, target):
    template = choose_template(name, target)
    payload = {
        "uuid": get_template_uuid(template),
        "settings": {
            "name": name,
            "enabled": True,
            "text_targets": target
        }
    }
    resp = session.post(f"{NESSUS_URL}/scans", json=payload)
    resp.raise_for_status()
    return resp.json()["scan"]["id"]

def get_template_uuid(template_name):
    resp = session.get(f"{NESSUS_URL}/editor/scan/templates")
    resp.raise_for_status()
    for t in resp.json()["templates"]:
        if t["name"] == template_name:
            return t["uuid"]
    raise ValueError(f"未找到模板：{template_name}")

def launch_scan(scan_id):
    resp = session.post(f"{NESSUS_URL}/scans/{scan_id}/launch")
    resp.raise_for_status()

def wait_for_scan(scan_id):
    while True:
        resp = session.get(f"{NESSUS_URL}/scans/{scan_id}")
        resp.raise_for_status()
        status = resp.json()["info"]["status"]
        if status == "completed":
            break
        elif status in ("canceled", "empty"):
            raise Exception(f"扫描失败：{status}")
        time.sleep(10)

def count_vulnerabilities(scan_details):
    levels = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for v in scan_details.get('vulnerabilities', []):
        sev = v.get("severity", 0)
        if sev >= 4: levels['critical'] += 1
        elif sev == 3: levels['high'] += 1
        elif sev == 2: levels['medium'] += 1
        elif sev == 1: levels['low'] += 1
    return levels

def export_pdf(scan_id, scan_name, report_dir):
    payload = {
        "format": "pdf",
        "chapters": "vuln_hosts_summary;vuln_by_host;compliance_exec;remediations;vuln_by_plugin"
    }
    export_resp = session.post(f"{NESSUS_URL}/scans/{scan_id}/export", json=payload)
    export_resp.raise_for_status()
    file_id = export_resp.json()["file"]

    for _ in range(30):
        status = session.get(f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status").json()
        if status.get("status") == "ready":
            break
        time.sleep(2)

    download = session.get(f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download")
    download.raise_for_status()

    filename = os.path.join(report_dir, f"{safe_filename(scan_name)}_漏洞报告.pdf")
    with open(filename, "wb") as f:
        f.write(download.content)
    return filename

def delete_scan(scan_id):
    session.delete(f"{NESSUS_URL}/scans/{scan_id}")

def read_tasks_from_csv(csv_path):
    df = pd.read_csv(csv_path)
    return df.to_dict("records")

def get_all_scans():
    resp = session.get(f"{NESSUS_URL}/scans")
    resp.raise_for_status()
    return resp.json().get("scans", [])

def get_scan_details(scan_id):
    for _ in range(3):
        try:
            r = session.get(f"{NESSUS_URL}/scans/{scan_id}")
            r.raise_for_status()
            return r.json()
        except:
            time.sleep(2)
    return None

def run_create_and_launch(csv_file):
    tasks = read_tasks_from_csv(csv_file)
    for task in tasks:
        name = str(task["任务名称"]).strip()
        target = str(task["ip地址"]).strip()
        print(f"创建任务：{name} → {target}")
        try:
            scan_id = create_scan(name, target)
            launch_scan(scan_id)
            print(f"任务 {name} 已启动")
        except Exception as e:
            print(f"创建或启动失败：{e}")

def run_report_export():
    report_dir = create_report_dir()
    scans = get_all_scans()
    report_data = []

    for scan in scans:
        scan_id = scan["id"]
        name = scan["name"]
        print(f"处理任务：{name}")

        try:
            wait_for_scan(scan_id)
            details = get_scan_details(scan_id)
            if not details:
                print(f"无法获取详情：{name}")
                continue

            vuln = count_vulnerabilities(details)
            report_data.append({
                "任务名称": name,
                "严重漏洞": vuln["critical"],
                "高危漏洞": vuln["high"],
                "中危漏洞": vuln["medium"],
                "低危漏洞": vuln["low"],
                "总数": sum(vuln.values())
            })

            pdf = export_pdf(scan_id, name, report_dir)
            print(f"PDF导出完成：{os.path.basename(pdf)}")

            delete_scan(scan_id)
            print(f"任务已删除：{name}")
        except Exception as e:
            print(f"任务 {name} 处理失败：{e}")

    if report_data:
        df = pd.DataFrame(report_data)
        excel_path = os.path.join(report_dir, "漏洞汇总.xlsx")
        df.to_excel(excel_path, index=False, engine="openpyxl")
        print(f"汇总文件已保存：{excel_path}")

# === 主入口 ===
if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1].endswith(".csv"):
        run_create_and_launch(sys.argv[1])
    else:
        run_report_export()
