from flask import Flask, render_template, jsonify
from threading import Thread
import logging

from ids import start_capture, stats, recent_packets


app = Flask(
    __name__,
    template_folder="ui/templates",
    static_folder="ui/static"
)


# Disable Flask request/access logs
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


@app.route("/")
def home():
    return render_template("dashboard.html")


@app.route("/api/stats")
def get_stats():
    return jsonify(stats)


@app.route("/api/packets")
def get_packets():
    return jsonify(list(recent_packets))


if __name__ == "__main__":
    capture_thread = Thread(target=start_capture, daemon=True)
    capture_thread.start()

    app.run(debug=True, use_reloader=False)