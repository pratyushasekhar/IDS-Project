from datetime import datetime

alerts = []

def add_alert(attack, source_ip, severity="High"):
    alert = {
        "attack": attack,
        "source_ip": source_ip,
        "severity": severity,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    alerts.append(alert)
    print("[ALERT]", alert)
    return alert

def get_alerts():
    return alerts

def get_alerts_by_attack(attack):
    return [a for a in alerts if a["attack"].lower() == attack.lower()]
