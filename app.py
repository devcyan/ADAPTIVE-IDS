from flask import Flask, render_template, jsonify
from threading import Thread

from ids import start_capture, stats


app = Flask(__name__, template_folder="ui/templates")


@app.route("/")
def home():
    return render_template("dashboard.html")


@app.route("/api/stats")
def get_stats():
    return jsonify(stats)


if __name__ == "__main__":
    capture_thread = Thread(target=start_capture, daemon=True)
    capture_thread.start()

    app.run(debug=True, use_reloader=False)