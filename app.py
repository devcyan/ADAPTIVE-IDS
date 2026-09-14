from flask import Flask, render_template, jsonify
from threading import Thread
import logging

from ids import start_capture, stats, recent_packets, alerts


# =========================
# Flask Application
# =========================

app = Flask(
    __name__,
    template_folder="ui/templates",
    static_folder="ui/static"
)


# =========================
# Flask Logging
# =========================

log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


# =========================
# Dashboard
# =========================

@app.route("/")
def home():
    return render_template("dashboard.html")


# =========================
# API - Statistics
# =========================

@app.route("/api/stats")
def get_stats():
    return jsonify(stats)


# =========================
# API - Recent Packets
# =========================

@app.route("/api/packets")
def get_packets():
    return jsonify(list(recent_packets))


# =========================
# API - Security Alerts
# =========================

@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(alerts))


# =========================
# Start Application
# =========================

if __name__ == "__main__":

    capture_thread = Thread(
        target=start_capture,
        daemon=True
    )

    capture_thread.start()

    app.run(
        debug=True,
        use_reloader=False
    )