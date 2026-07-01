"""from flask import Blueprint, render_template, request

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
def home():
    return render_template("home.html")
"""


from flask import Blueprint, render_template, request
from .alerts import add_alert
import time

views = Blueprint('views', __name__)

http_hits = {}
HTTP_WINDOW = 3
HTTP_THRESHOLD = 100

@views.route('/', methods=['GET', 'POST'])
def home():
    src = request.remote_addr
    now = time.time()

    http_hits.setdefault(src, [])
    http_hits[src].append(now)
    http_hits[src] = [t for t in http_hits[src] if now - t <= HTTP_WINDOW]

    if len(http_hits[src]) == HTTP_THRESHOLD:
        add_alert("HTTP Flood", src, "High")

    return render_template("home.html")
