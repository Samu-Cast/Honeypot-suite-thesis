from flask import Flask, render_template, jsonify
import sqlite3
import os
import json

app = Flask(__name__)

DB_PATH = "/data/correlations.db"


def get_db():
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _has_table(cursor, table_name):
    """Check if a table exists in the database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None


@app.route("/")
def index():
    conn = get_db()
    empty_stats = {
        "total": 0, "unique_ips": 0, "patterns": [],
        "top_countries": [], "top_asns": [], "enriched_ips": 0
    }
    if conn is None:
        return render_template("index.html", correlations=[], stats=empty_stats,
                               has_intel=False, chart_labels='[]', chart_data='[]',
                               country_labels='[]', country_data='[]')

    cursor = conn.cursor()
    has_intel = _has_table(cursor, "ip_intel")

    # get latest 100 correlations joined with ip_intel (if available)
    if has_intel:
        cursor.execute('''
            SELECT c.*, i.country, i.country_code, i.isp, i.asn, i.is_proxy, i.is_hosting
            FROM correlations c
            LEFT JOIN ip_intel i ON c.source_ip = i.ip
            ORDER BY c.timestamp DESC LIMIT 100
        ''')
    else:
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

    # IP intelligence stats
    top_countries = []
    top_asns = []
    enriched_ips = 0
    if has_intel:
        cursor.execute("SELECT COUNT(*) FROM ip_intel")
        enriched_ips = cursor.fetchone()[0]

        cursor.execute('''
            SELECT i.country, i.country_code, COUNT(*) as cnt
            FROM correlations c
            JOIN ip_intel i ON c.source_ip = i.ip
            WHERE i.country IS NOT NULL
            GROUP BY i.country, i.country_code
            ORDER BY cnt DESC LIMIT 10
        ''')
        top_countries = [(r["country"], r["country_code"], r["cnt"]) for r in cursor.fetchall()]

        cursor.execute('''
            SELECT i.asn, i.isp, COUNT(*) as cnt
            FROM correlations c
            JOIN ip_intel i ON c.source_ip = i.ip
            WHERE i.asn IS NOT NULL
            GROUP BY i.asn, i.isp
            ORDER BY cnt DESC LIMIT 10
        ''')
        top_asns = [(r["asn"], r["isp"], r["cnt"]) for r in cursor.fetchall()]

    conn.close()

    stats = {
        "total": total,
        "unique_ips": unique_ips,
        "patterns": [(r["pattern"], r["cnt"]) for r in pattern_counts],
        "top_countries": top_countries,
        "top_asns": top_asns,
        "enriched_ips": enriched_ips,
    }

    # pre-build chart data for the template
    chart_labels = json.dumps([r["pattern"] for r in pattern_counts])
    chart_data = json.dumps([r["cnt"] for r in pattern_counts])
    country_labels = json.dumps([c[0] for c in top_countries])
    country_data = json.dumps([c[2] for c in top_countries])

    return render_template("index.html", correlations=correlations, stats=stats,
                           chart_labels=chart_labels, chart_data=chart_data,
                           country_labels=country_labels, country_data=country_data,
                           has_intel=has_intel)


@app.route("/api/stats")
def api_stats():
    """JSON endpoint for live polling. Returns the same data as the index page
    but serialized as JSON so the frontend can update without a full page reload."""
    conn = get_db()
    if conn is None:
        return jsonify({"total": 0, "unique_ips": 0, "patterns": [],
                        "top_countries": [], "top_asns": [], "enriched_ips": 0,
                        "recent_sessions": []})

    cursor = conn.cursor()
    has_intel = _has_table(cursor, "ip_intel")

    cursor.execute("SELECT COUNT(*) FROM correlations")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM correlations")
    unique_ips = cursor.fetchone()[0]

    cursor.execute("SELECT pattern, COUNT(*) as cnt FROM correlations GROUP BY pattern ORDER BY cnt DESC")
    patterns = [(r["pattern"], r["cnt"]) for r in cursor.fetchall()]

    enriched_ips = 0
    top_countries = []
    top_asns = []
    if has_intel:
        cursor.execute("SELECT COUNT(*) FROM ip_intel")
        enriched_ips = cursor.fetchone()[0]

        cursor.execute('''
            SELECT i.country, i.country_code, COUNT(*) as cnt
            FROM correlations c JOIN ip_intel i ON c.source_ip = i.ip
            WHERE i.country IS NOT NULL
            GROUP BY i.country, i.country_code ORDER BY cnt DESC LIMIT 10
        ''')
        top_countries = [{"country": r["country"], "country_code": r["country_code"], "cnt": r["cnt"]}
                         for r in cursor.fetchall()]

        cursor.execute('''
            SELECT i.asn, i.isp, COUNT(*) as cnt
            FROM correlations c JOIN ip_intel i ON c.source_ip = i.ip
            WHERE i.asn IS NOT NULL
            GROUP BY i.asn, i.isp ORDER BY cnt DESC LIMIT 10
        ''')
        top_asns = [{"asn": r["asn"], "isp": r["isp"], "cnt": r["cnt"]} for r in cursor.fetchall()]

    # last 20 sessions for the live table
    if has_intel:
        cursor.execute('''
            SELECT c.timestamp, c.source_ip, c.pattern,
                   c.hits_cowrie, c.hits_dionaea, c.hits_opencanary,
                   c.first_seen, c.last_seen,
                   i.country, i.country_code, i.isp, i.is_proxy, i.is_hosting
            FROM correlations c LEFT JOIN ip_intel i ON c.source_ip = i.ip
            ORDER BY c.timestamp DESC LIMIT 20
        ''')
    else:
        cursor.execute('''
            SELECT timestamp, source_ip, pattern,
                   hits_cowrie, hits_dionaea, hits_opencanary, first_seen, last_seen
            FROM correlations ORDER BY timestamp DESC LIMIT 20
        ''')

    recent_sessions = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "total": total,
        "unique_ips": unique_ips,
        "patterns": [{"pattern": p, "cnt": c} for p, c in patterns],
        "top_countries": top_countries,
        "top_asns": top_asns,
        "enriched_ips": enriched_ips,
        "recent_sessions": recent_sessions,
        "has_intel": has_intel,
    })


@app.route("/ip/<ip_address>")
def ip_detail(ip_address):
    """Detail page for a single IP: shows all intel + all sessions from that IP."""
    conn = get_db()
    if conn is None:
        return "Database not available", 503

    cursor = conn.cursor()

    # get intel
    intel = None
    if _has_table(cursor, "ip_intel"):
        cursor.execute("SELECT * FROM ip_intel WHERE ip = ?", (ip_address,))
        intel = cursor.fetchone()

    # get all sessions for this IP
    cursor.execute("""
        SELECT * FROM correlations
        WHERE source_ip = ?
        ORDER BY timestamp DESC
    """, (ip_address,))
    sessions = cursor.fetchall()

    conn.close()
    return render_template("ip_detail.html", ip=ip_address, intel=intel, sessions=sessions)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
