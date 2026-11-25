from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import json
import csv
import io
from datetime import datetime, timedelta
from analyzer import EmailAnalyzer, URLAnalyzer

app = Flask(__name__)
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200/day", "50/hour"])

DB_PATH = os.environ.get("DATABASE_PATH", "threats.db")

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        # Scans table - WITHOUT user_ip and user_agent
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT    NOT NULL,
                content   TEXT    NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict   TEXT    NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                category    TEXT NOT NULL,
                severity    TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS breakdown (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                category    TEXT NOT NULL,
                score       INTEGER NOT NULL,
                details     TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS batch_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_name  TEXT NOT NULL,
                total_urls  INTEGER NOT NULL,
                high_risk   INTEGER NOT NULL,
                suspicious  INTEGER NOT NULL,
                safe        INTEGER NOT NULL,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE IF NOT EXISTS batch_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id    INTEGER NOT NULL,
                url         TEXT NOT NULL,
                risk_score  INTEGER NOT NULL,
                verdict     TEXT NOT NULL,
                findings    TEXT,
                FOREIGN KEY(batch_id) REFERENCES batch_scans(id) ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS threat_intel (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT UNIQUE NOT NULL,
                threat_level INTEGER NOT NULL,
                reason      TEXT,
                added_date  DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Create indexes
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk ON scans(risk_score)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_domain ON threat_intel(domain)")

init_db()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def verdict_from_score(score: int) -> str:
    if score <= 20: return "Safe"
    if score <= 50: return "Suspicious"
    if score <= 80: return "High Risk"
    return "Critical Threat"

def get_risk_level(score: int) -> str:
    if score <= 20: return "low"
    if score <= 50: return "medium"
    if score <= 80: return "high"
    return "critical"

def save_scan(scan_type, content, risk_score, verdict, findings, breakdown=None):
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO scans (scan_type, content, risk_score, verdict) VALUES (?, ?, ?, ?)",
            (scan_type, content[:2000], risk_score, verdict)
        )
        scan_id = cur.lastrowid
        
        for f in findings:
            db.execute(
                "INSERT INTO findings (scan_id, category, severity, description, recommendation) VALUES (?, ?, ?, ?, ?)",
                (scan_id, f.get("category", "General"), f.get("severity", "Medium"), 
                 f.get("description", ""), f.get("recommendation", ""))
            )
        
        if breakdown:
            for category, details in breakdown.items():
                score_value = details.get("score", 0) if isinstance(details, dict) else 0
                db.execute(
                    "INSERT INTO breakdown (scan_id, category, score, details) VALUES (?, ?, ?, ?)",
                    (scan_id, category, score_value, json.dumps(details))
                )
        
        # Add to threat intelligence if high risk
        if risk_score >= 70:
            domain = extract_domain(content) if scan_type == 'url' else None
            if domain:
                db.execute(
                    "INSERT OR IGNORE INTO threat_intel (domain, threat_level, reason) VALUES (?, ?, ?)",
                    (domain, risk_score, f"Detected by scan #{scan_id}")
                )
        
        db.commit()
    return scan_id

def extract_domain(content):
    import re
    match = re.search(r'https?://([^/]+)', content)
    return match.group(1) if match else None

# ============================================================================
# MAIN ROUTES
# ============================================================================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signin")
@app.route("/signin.html")
def signin():
    return render_template("signin.html")

# ============================================================================
# SCAN ENDPOINTS
# ============================================================================

@app.route("/api/scan/email", methods=["POST"])
@limiter.limit("15/minute")
def scan_email():
    try:
        data = request.get_json(force=True)
        content = (data.get("content") or "").strip()
        if not content:
            return jsonify({"error": "Email content is required"}), 400
        
        result = EmailAnalyzer(content).analyze()
        verdict = verdict_from_score(result["risk_score"])
        scan_id = save_scan("email", content, result["risk_score"], verdict, 
                           result.get("findings", []), result.get("breakdown", {}))
        
        return jsonify({
            "scan_id": scan_id,
            "risk_score": result["risk_score"],
            "risk_level": get_risk_level(result["risk_score"]),
            "verdict": verdict,
            "summary": result.get("summary", "Analysis complete"),
            "findings": result.get("findings", []),
            "breakdown": result.get("breakdown", {}),
            "extracted_urls": result.get("extracted_urls", []),
            "recommendations": result.get("recommendations", []),
            "success": True
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/scan/url", methods=["POST"])
@limiter.limit("20/minute")
def scan_url():
    try:
        data = request.get_json(force=True)
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        result = URLAnalyzer(url).analyze()
        verdict = verdict_from_score(result["risk_score"])
        scan_id = save_scan("url", url, result["risk_score"], verdict,
                           result.get("findings", []), result.get("breakdown", {}))
        
        return jsonify({
            "scan_id": scan_id,
            "risk_score": result["risk_score"],
            "risk_level": get_risk_level(result["risk_score"]),
            "verdict": verdict,
            "summary": result.get("summary", "Analysis complete"),
            "findings": result.get("findings", []),
            "breakdown": result.get("breakdown", {}),
            "domain": result.get("domain", ""),
            "features": result.get("features", {}),
            "recommendations": result.get("recommendations", []),
            "success": True
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# BATCH SCAN ENDPOINTS
# ============================================================================

@app.route("/api/scan/batch", methods=["POST"])
@limiter.limit("5/minute")
def scan_batch():
    try:
        data = request.get_json(force=True)
        urls = data.get("urls", [])
        
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400
        if len(urls) > 20:
            return jsonify({"error": "Maximum 20 URLs per batch"}), 400
        
        results = []
        high_risk = 0
        suspicious = 0
        safe = 0
        
        for url in urls:
            url = url.strip()
            if not url:
                continue
            
            result = URLAnalyzer(url).analyze()
            risk = result["risk_score"]
            verdict = verdict_from_score(risk)
            
            if risk >= 70:
                high_risk += 1
            elif risk >= 40:
                suspicious += 1
            else:
                safe += 1
            
            results.append({
                "url": url,
                "risk_score": risk,
                "risk_level": get_risk_level(risk),
                "verdict": verdict,
                "findings": result.get("findings", [])[:3],
                "summary": result.get("summary", "")
            })
        
        # Save batch to database
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO batch_scans (batch_name, total_urls, high_risk, suspicious, safe) VALUES (?, ?, ?, ?, ?)",
                (f"Batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}", len(results), high_risk, suspicious, safe)
            )
            batch_id = cur.lastrowid
            
            for r in results:
                db.execute(
                    "INSERT INTO batch_results (batch_id, url, risk_score, verdict, findings) VALUES (?, ?, ?, ?, ?)",
                    (batch_id, r["url"], r["risk_score"], r["verdict"], json.dumps(r["findings"]))
                )
            db.commit()
        
        return jsonify({
            "success": True,
            "batch_id": batch_id,
            "total": len(results),
            "high_risk": high_risk,
            "suspicious": suspicious,
            "safe": safe,
            "results": results
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/batch/<int:batch_id>", methods=["GET"])
def get_batch_results(batch_id):
    try:
        with get_db() as db:
            batch = db.execute("SELECT * FROM batch_scans WHERE id = ?", (batch_id,)).fetchone()
            if not batch:
                return jsonify({"error": "Batch not found"}), 404
            
            results = db.execute("SELECT * FROM batch_results WHERE batch_id = ?", (batch_id,)).fetchall()
            
            return jsonify({
                "batch": dict(batch),
                "results": [dict(r) for r in results]
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# HISTORY & FILTERS
# ============================================================================

@app.route("/api/history", methods=["GET"])
def history():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = int(request.args.get("offset", 0))
        scan_type = request.args.get("type", None)
        min_risk = request.args.get("min_risk", None, type=int)
        search = request.args.get("search", None)
        
        with get_db() as db:
            query = "SELECT id, scan_type, content, risk_score, verdict, timestamp FROM scans WHERE 1=1"
            params = []
            
            if scan_type and scan_type != 'all':
                query += " AND scan_type = ?"
                params.append(scan_type)
            
            if min_risk is not None:
                query += " AND risk_score >= ?"
                params.append(min_risk)
            
            if search:
                query += " AND content LIKE ?"
                params.append(f"%{search}%")
            
            # Get total count
            count_query = query.replace("SELECT id, scan_type, content, risk_score, verdict, timestamp", "SELECT COUNT(*)")
            total = db.execute(count_query, params).fetchone()[0]
            
            # Get paginated results
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            rows = db.execute(query, params).fetchall()
            
            history_list = []
            for row in rows:
                history_list.append({
                    "id": row["id"],
                    "type": row["scan_type"],
                    "content": row["content"][:100] + "..." if len(row["content"]) > 100 else row["content"],
                    "full_content": row["content"],
                    "risk_score": row["risk_score"],
                    "risk_level": get_risk_level(row["risk_score"]),
                    "verdict": row["verdict"],
                    "timestamp": row["timestamp"]
                })
            
            return jsonify({
                "history": history_list,
                "total": total,
                "limit": limit,
                "offset": offset
            })
    except Exception as e:
        return jsonify({"error": str(e), "history": []}), 500

@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    try:
        with get_db() as db:
            scan = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not scan:
                return jsonify({"error": "Not found"}), 404
            
            findings = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
            breakdown = db.execute("SELECT category, score, details FROM breakdown WHERE scan_id = ?", (scan_id,)).fetchall()
            
            breakdown_dict = {}
            for b in breakdown:
                breakdown_dict[b["category"]] = {"score": b["score"], "details": json.loads(b["details"]) if b["details"] else {}}
            
            return jsonify({
                "id": scan["id"],
                "type": scan["scan_type"],
                "content": scan["content"],
                "risk_score": scan["risk_score"],
                "risk_level": get_risk_level(scan["risk_score"]),
                "verdict": scan["verdict"],
                "timestamp": scan["timestamp"],
                "findings": [dict(f) for f in findings],
                "breakdown": breakdown_dict,
                "summary": scan["verdict"]
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# STATISTICS & ANALYTICS
# ============================================================================

@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        with get_db() as db:
            # Basic stats
            total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            threats = db.execute("SELECT COUNT(*) FROM scans WHERE risk_score > 50").fetchone()[0]
            avg_score = db.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
            high_risk = db.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 70").fetchone()[0]
            critical = db.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 90").fetchone()[0]
            
            # Scans by type
            email_count = db.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'email'").fetchone()[0]
            url_count = db.execute("SELECT COUNT(*) FROM scans WHERE scan_type = 'url'").fetchone()[0]
            
            # Today's scans
            today = datetime.now().strftime('%Y-%m-%d')
            today_scans = db.execute("SELECT COUNT(*) FROM scans WHERE DATE(timestamp) = ?", (today,)).fetchone()[0]
            
            # Weekly trend (last 7 days)
            weekly = db.execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count, AVG(risk_score) as avg_risk
                FROM scans 
                WHERE timestamp >= DATE('now', '-7 days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            """).fetchall()
            
            # Risk distribution
            risk_distribution = db.execute("""
                SELECT 
                    CASE 
                        WHEN risk_score <= 20 THEN 'Safe'
                        WHEN risk_score <= 50 THEN 'Suspicious'
                        WHEN risk_score <= 80 THEN 'High Risk'
                        ELSE 'Critical'
                    END as level,
                    COUNT(*) as count
                FROM scans
                GROUP BY level
            """).fetchall()
            
            # Top findings categories
            top_findings = db.execute("""
                SELECT category, COUNT(*) as count
                FROM findings
                GROUP BY category
                ORDER BY count DESC
                LIMIT 5
            """).fetchall()
            
            return jsonify({
                "total_scans": total,
                "threats_found": threats,
                "average_risk_score": round(avg_score, 1),
                "high_risk_threats": high_risk,
                "critical_threats": critical,
                "email_scans": email_count,
                "url_scans": url_count,
                "today_scans": today_scans,
                "detection_rate": round((high_risk + critical) / max(total, 1) * 100, 1),
                "weekly_trend": [dict(row) for row in weekly],
                "risk_distribution": [dict(row) for row in risk_distribution],
                "top_findings": [dict(row) for row in top_findings]
            })
    except Exception as e:
        return jsonify({
            "total_scans": 0,
            "threats_found": 0,
            "average_risk_score": 0,
            "high_risk_threats": 0,
            "critical_threats": 0,
            "email_scans": 0,
            "url_scans": 0,
            "today_scans": 0,
            "detection_rate": 0,
            "weekly_trend": [],
            "risk_distribution": [],
            "top_findings": []
        }), 200

# ============================================================================
# EXPORT ENDPOINTS
# ============================================================================

@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    try:
        scan_type = request.args.get("type", None)
        min_risk = request.args.get("min_risk", None, type=int)
        
        with get_db() as db:
            query = "SELECT id, scan_type, content, risk_score, verdict, timestamp FROM scans WHERE 1=1"
            params = []
            
            if scan_type and scan_type != 'all':
                query += " AND scan_type = ?"
                params.append(scan_type)
            
            if min_risk is not None:
                query += " AND risk_score >= ?"
                params.append(min_risk)
            
            query += " ORDER BY id DESC"
            rows = db.execute(query, params).fetchall()
            
            # Create CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Type', 'Content', 'Risk Score', 'Verdict', 'Timestamp'])
            
            for row in rows:
                writer.writerow([
                    row['id'], row['scan_type'], row['content'][:500],
                    row['risk_score'], row['verdict'], row['timestamp']
                ])
            
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'threatlens_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/export/json", methods=["GET"])
def export_json():
    try:
        with get_db() as db:
            scans = db.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
            results = []
            
            for scan in scans:
                findings = db.execute("SELECT * FROM findings WHERE scan_id = ?", (scan['id'],)).fetchall()
                results.append({
                    "scan": dict(scan),
                    "findings": [dict(f) for f in findings]
                })
            
            return jsonify({
                "export_date": datetime.now().isoformat(),
                "total_scans": len(results),
                "data": results
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# THREAT INTELLIGENCE ENDPOINTS
# ============================================================================

@app.route("/api/threat-intel", methods=["GET"])
def get_threat_intel():
    try:
        with get_db() as db:
            threats = db.execute(
                "SELECT domain, threat_level, reason, added_date FROM threat_intel ORDER BY threat_level DESC LIMIT 100"
            ).fetchall()
            return jsonify({"threats": [dict(t) for t in threats]})
    except Exception as e:
        return jsonify({"error": str(e), "threats": []}), 500

@app.route("/api/threat-intel/check", methods=["POST"])
def check_threat_intel():
    try:
        data = request.get_json(force=True)
        domain = data.get("domain", "")
        
        with get_db() as db:
            threat = db.execute("SELECT * FROM threat_intel WHERE domain = ?", (domain,)).fetchone()
            
            if threat:
                return jsonify({
                    "is_threat": True,
                    "threat_level": threat['threat_level'],
                    "reason": threat['reason'],
                    "added_date": threat['added_date']
                })
            else:
                return jsonify({"is_threat": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    """Legacy endpoint for compatibility"""
    return stats()

@app.route("/api/health", methods=["GET"])
def health_check():
    try:
        with get_db() as db:
            db.execute("SELECT 1")
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0"
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  ThreatLens Pro Security Platform - FULL VERSION")
    print("=" * 70)
    print(f"📁 Database: {DB_PATH}")
    print(f"🌐 Server: http://0.0.0.0:5000")
    print(f"📱 Dashboard: http://localhost:5000")
    print("=" * 70)
    print("\n✅ FEATURES ENABLED:")
    print("   • Email & URL Scanning")
    print("   • Batch URL Scanning (up to 20 URLs)")
    print("   • Scan History with Filters")
    print("   • Export to CSV/JSON")
    print("   • Threat Intelligence Database")
    print("   • Analytics & Statistics")
    print("   • Risk Distribution Charts")
    print("   • Weekly Trend Analysis")
    print("=" * 70)
    app.run(host="0.0.0.0", port=5000, debug=True)
