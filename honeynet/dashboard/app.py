from flask import Flask, render_template
import sqlite3
import os
import json

app = Flask(__name__)

DB_PATH = "/data/correlations.db"


def get_db():
    """get a connection to the correlations database, returns None if db doesnt exist yet"""
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_db()
    if conn is None:
        return render_template("index.html", correlations=[], stats={
            "total": 0, "unique_ips": 0, "patterns": []
        })

    cursor = conn.cursor()

    # get latest 100 correlations
    cursor.execute("SELECT * FROM correlations ORDER BY timestamp DESC LIMIT 100")
    correlations = cursor.fetchall()

    # count by pattern
    cursor.execute("SELECT pattern, COUNT(*) as cnt FROM correlations GROUP BY pattern ORDER BY cnt DESC")
    pattern_counts = cursor.fetchall()

    # some basic stats
    cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM correlations")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM correlations")
    total = cursor.fetchone()[0]

    conn.close()

    stats = {
        "total": total,
        "unique_ips": unique_ips,
        "patterns": [(r["pattern"], r["cnt"]) for r in pattern_counts]
    }

    # pre-build chart data for the template
    chart_labels = json.dumps([r["pattern"] for r in pattern_counts])
    chart_data = json.dumps([r["cnt"] for r in pattern_counts])

    return render_template("index.html", correlations=correlations, stats=stats,
                           chart_labels=chart_labels, chart_data=chart_data)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
