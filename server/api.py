from flask import Blueprint, jsonify
from .alerts import get_alerts, get_alerts_by_attack

api = Blueprint("api", __name__)

@api.route("/ids-alerts", methods=["GET"])
def ids_alerts():
    return jsonify(get_alerts())

@api.route("/ids-alerts/<attack>", methods=["GET"])
def ids_alerts_by_attack(attack):
    return jsonify(get_alerts_by_attack(attack))

@api.route("/test-alert", methods=["GET"])
def test_alert():
    from .alerts import add_alert
    add_alert("Port Scan", "192.168.1.178", "High")
    return jsonify({"status": "added"})
