import requests  
import pandas as pd  
import matplotlib.pyplot as plt  
import json  
from datetime import datetime  
import time  

# Этап 1: Сбор данных  
# Имитация логов Suricata
suricata_logs = [  
    {"timestamp": "2026-03-17T14:00:01", "src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "event": "dns_query", "count": 50},  
    {"timestamp": "2026-03-17T14:01:15", "src_ip": "192.168.1.101", "dst_ip": "93.184.216.34", "event": "http_request", "count": 5},  
    {"timestamp": "2026-03-17T14:02:30", "src_ip": "192.168.1.100", "dst_ip": "malicious.com", "event": "dns_query", "count": 150},  # Подозрительно много  
    {"timestamp": "2026-03-17T14:03:45", "src_ip": "10.0.0.5", "dst_ip": "scanme.nmap.org", "event": "port_scan", "count": 20}  
]  

# API Vulners (замените YOUR_API_KEY на реальный ключ)  
VULNERS_API_KEY = "YOUR_API_KEY"  # Получите бесплатно на vulners.com  
def get_vulners_data():  
    url = f"https://vulners.com/api/v3/search/lucene/?apiKey={VULNERS_API_KEY}&query=apache&size=5"  
    try:  
        response = requests.get(url, timeout=10)  
        data = response.json()  
        vulns = []  
        for vuln in data.get('data', {}).get('search', []):  
            cvss = vuln.get('cvss', {}).get('score', 0)  
            if cvss > 7:  # Высокий риск  
                vulns.append({"id": vuln['id'], "title": vuln['title'], "cvss": cvss})  
        return vulns  
    except:  
        # Fallback: имитация данных для тестирования  
        return [  
            {"id": "CVE-2023-1234", "title": "Apache Critical RCE", "cvss": 9.8},  
            {"id": "CVE-2025-5678", "title": "DNS Amplification", "cvss": 8.1}  
        ]  

vulners_threats = get_vulners_data()  

# Этап 2: Анализ данных  
df_logs = pd.DataFrame(suricata_logs)  
suspicious_ips = df_logs[df_logs['count'] > 100]['src_ip'].unique()  # Подозрительный трафик  
threats = []  

for ip in suspicious_ips:  
    threats.append({"type": "high_dns", "ip": ip, "severity": "high", "timestamp": datetime.now().isoformat()})  

for vuln in vulners_threats:  
    threats.append({"type": "vulnerability", "cve": vuln['id'], "cvss": vuln['cvss'], "timestamp": datetime.now().isoformat()})  

print(f"Обнаружено угроз: {len(threats)}")

# Этап 3: Реагирование  
for threat in threats:  
    if threat['type'] == 'high_dns':  
        print(f"УГРОЗА: Блокировка IP {threat['ip']} (имитация: добавлен в blacklist)")  
    elif threat['type'] == 'vulnerability':  
        print(f"УГРОЗА: Высокий CVSS {threat['cvss']} для {threat['cve']}. Рекомендация: обновить ПО")  
    time.sleep(0.5)  # Имитация задержки реагирования  

# Этап 4: Отчет и визуализация  
report = {  
    "analysis_date": datetime.now().isoformat(),  
    "total_threats": len(threats),  
    "suspicious_ips": list(suspicious_ips),  
    "high_cvss_vulns": [v for v in vulners_threats if v['cvss'] > 7],  
    "threats": threats  
}  

# Сохранение JSON  
with open('threat_report.json', 'w') as f:  
    json.dump(report, f, indent=2)  

# Сохранение CSV  
df_threats = pd.DataFrame(threats)  
df_threats.to_csv('threat_report.csv', index=False)  

# График: Распределение угроз по типу и severity  
fig, ax = plt.subplots(1, 2, figsize=(12, 5))  
df_logs['event'].value_counts().plot(kind='bar', ax=ax[0])  
ax[0].set_title('Топ событий из логов')  
ax[0].tick_params(axis='x', rotation=45)  

cvss_scores = [v['cvss'] for v in vulners_threats]  
ax[1].hist(cvss_scores, bins=5, alpha=0.7)  
ax[1].set_title('Распределение CVSS-баллов')  
ax[1].set_xlabel('CVSS Score')  

plt.tight_layout()  
plt.savefig('threats_plot.png')  
plt.show()  

print("Отчеты и график сохранены.")  
