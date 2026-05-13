from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import os
import json
from datetime import datetime
from analyzer import EmailAnalyzer, URLAnalyzer

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get("DATABASE_PATH", "threats.db")

# ─── Database Functions ─────────────────────────────────────────────────────

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with all required tables"""
    with get_db() as db:
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
        """)
        
        # Create indexes for better performance
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")

# Initialize database on startup
init_db()

# ─── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template("index.html")

@app.route('/api/scan/url', methods=['POST'])
def scan_url_endpoint():
    """Scan a URL and save results"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Analyze URL using your analyzer
        analyzer = URLAnalyzer(url)
        result = analyzer.analyze()
        
        # Save to database
        with get_db() as db:
            # Insert scan record
            cursor = db.execute(
                "INSERT INTO scans (scan_type, content, risk_score, verdict) VALUES (?, ?, ?, ?)",
                ('url', url, result['risk_score'], result.get('summary', 'Analysis complete'))
            )
            scan_id = cursor.lastrowid
            
            # Save findings
            for finding in result.get('findings', []):
                db.execute(
                    """INSERT INTO findings (scan_id, category, severity, description, recommendation) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (scan_id, 
                     finding.get('category', 'General'),
                     finding.get('severity', 'Medium'),
                     finding.get('description', 'No description'),
                     finding.get('recommendation', 'Exercise caution'))
                )
            
            # Save breakdown if available
            breakdown = result.get('breakdown', {})
            for category, details in breakdown.items():
                score_value = details.get('score', 0) if isinstance(details, dict) else 0
                db.execute(
                    "INSERT INTO breakdown (scan_id, category, score, details) VALUES (?, ?, ?, ?)",
                    (scan_id, category, score_value, json.dumps(details))
                )
            
            db.commit()
        
        # Add scan_id to response
        result['scan_id'] = scan_id
        result['success'] = True
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan/email', methods=['POST'])
def scan_email_endpoint():
    """Scan email content and save results"""
    try:
        data = request.json
        email_content = data.get('content', '')
        
        if not email_content:
            return jsonify({"error": "No email content provided"}), 400
        
        # Analyze email using your analyzer
        analyzer = EmailAnalyzer(email_content)
        result = analyzer.analyze()
        
        # Save to database
        with get_db() as db:
            # Insert scan record (truncate content for storage)
            truncated_content = email_content[:500] if len(email_content) > 500 else email_content
            cursor = db.execute(
                "INSERT INTO scans (scan_type, content, risk_score, verdict) VALUES (?, ?, ?, ?)",
                ('email', truncated_content, result['risk_score'], result.get('summary', 'Analysis complete'))
            )
            scan_id = cursor.lastrowid
            
            # Save findings
            for finding in result.get('findings', []):
                db.execute(
                    """INSERT INTO findings (scan_id, category, severity, description, recommendation) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (scan_id,
                     finding.get('category', 'General'),
                     finding.get('severity', 'Medium'),
                     finding.get('description', 'No description'),
                     finding.get('recommendation', 'Exercise caution'))
                )
            
            # Save breakdown
            breakdown = result.get('breakdown', {})
            for category, details in breakdown.items():
                score_value = details.get('score', 0) if isinstance(details, dict) else 0
                db.execute(
                    "INSERT INTO breakdown (scan_id, category, score, details) VALUES (?, ?, ?, ?)",
                    (scan_id, category, score_value, json.dumps(details))
                )
            
            db.commit()
        
        result['scan_id'] = scan_id
        result['success'] = True
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Get scan history with optional filters"""
    try:
        # Get query parameters
        limit = request.args.get('limit', 50, type=int)
        scan_type = request.args.get('type', None)
        min_risk = request.args.get('min_risk', None, type=int)
        
        with get_db() as db:
            # Build query
            query = "SELECT * FROM scans"
            params = []
            conditions = []
            
            if scan_type and scan_type != 'all':
                conditions.append("scan_type = ?")
                params.append(scan_type)
            
            if min_risk is not None:
                conditions.append("risk_score >= ?")
                params.append(min_risk)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            scans = db.execute(query, params).fetchall()
            
            results = []
            for scan in scans:
                # Get findings for this scan
                findings = db.execute(
                    "SELECT category, severity, description FROM findings WHERE scan_id = ? LIMIT 3",
                    (scan['id'],)
                ).fetchall()
                
                results.append({
                    "id": scan['id'],
                    "type": scan['scan_type'],
                    "content": scan['content'][:100] + "..." if len(scan['content']) > 100 else scan['content'],
                    "risk_score": scan['risk_score'],
                    "verdict": scan['verdict'],
                    "timestamp": scan['timestamp'],
                    "findings_count": len(findings),
                    "top_finding": findings[0]['description'] if findings else None
                })
            
            return jsonify({"history": results, "total": len(results)})
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e), "history": []}), 500

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """Get detailed information for a specific scan"""
    try:
        with get_db() as db:
            # Get scan details
            scan = db.execute(
                "SELECT * FROM scans WHERE id = ?",
                (scan_id,)
            ).fetchone()
            
            if not scan:
                return jsonify({"error": "Scan not found"}), 404
            
            # Get findings
            findings = db.execute(
                "SELECT category, severity, description, recommendation FROM findings WHERE scan_id = ?",
                (scan_id,)
            ).fetchall()
            
            # Get breakdown
            breakdown = db.execute(
                "SELECT category, score, details FROM breakdown WHERE scan_id = ?",
                (scan_id,)
            ).fetchall()
            
            # Build breakdown dictionary
            breakdown_dict = {}
            for b in breakdown:
                breakdown_dict[b['category']] = {
                    "score": b['score'],
                    "details": json.loads(b['details']) if b['details'] else {}
                }
            
            return jsonify({
                "id": scan['id'],
                "type": scan['scan_type'],
                "content": scan['content'],
                "risk_score": scan['risk_score'],
                "verdict": scan['verdict'],
                "timestamp": scan['timestamp'],
                "findings": [dict(f) for f in findings],
                "breakdown": breakdown_dict,
                "summary": scan['verdict']
            })
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        with get_db() as db:
            # Total scans
            total = db.execute("SELECT COUNT(*) as count FROM scans").fetchone()['count']
            
            # Average risk score
            avg_risk = db.execute("SELECT AVG(risk_score) as avg FROM scans").fetchone()['avg'] or 0
            
            # High risk threats (score >= 50)
            high_risk = db.execute(
                "SELECT COUNT(*) as count FROM scans WHERE risk_score >= 50"
            ).fetchone()['count']
            
            # Critical threats (score >= 80)
            critical = db.execute(
                "SELECT COUNT(*) as count FROM scans WHERE risk_score >= 80"
            ).fetchone()['count']
            
            # Scans by type
            email_count = db.execute(
                "SELECT COUNT(*) as count FROM scans WHERE scan_type = 'email'"
            ).fetchone()['count']
            
            url_count = db.execute(
                "SELECT COUNT(*) as count FROM scans WHERE scan_type = 'url'"
            ).fetchone()['count']
            
            # Today's scans
            today = datetime.now().strftime('%Y-%m-%d')
            today_scans = db.execute(
                "SELECT COUNT(*) as count FROM scans WHERE DATE(timestamp) = DATE(?)",
                (today,)
            ).fetchone()['count']
            
            # Weekly trend (last 6 weeks)
            weekly_trend = db.execute("""
                SELECT 
                    strftime('%W', timestamp) as week,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk
                FROM scans 
                WHERE timestamp >= DATE('now', '-6 weeks')
                GROUP BY week
                ORDER BY week DESC
            """).fetchall()
            
            return jsonify({
                "total_scans": total,
                "average_risk_score": round(avg_risk, 1),
                "high_risk_threats": high_risk,
                "critical_threats": critical,
                "email_scans": email_count,
                "url_scans": url_count,
                "today_scans": today_scans,
                "weekly_trend": [dict(row) for row in weekly_trend],
                "detection_rate": round((high_risk + critical) / max(total, 1) * 100, 1)
            })
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "total_scans": 0,
            "average_risk_score": 0,
            "high_risk_threats": 0,
            "critical_threats": 0,
            "email_scans": 0,
            "url_scans": 0,
            "today_scans": 0,
            "weekly_trend": [],
            "detection_rate": 0
        }), 200

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    """Clear all scan history (admin only - add auth in production)"""
    try:
        with get_db() as db:
            db.execute("DELETE FROM findings")
            db.execute("DELETE FROM breakdown")
            db.execute("DELETE FROM scans")
            db.commit()
        
        return jsonify({"success": True, "message": "History cleared successfully"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        with get_db() as db:
            db.execute("SELECT 1")
        return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# ─── Run the App ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  ThreatLens Pro Security Platform")
    print("=" * 60)
    print(f"📊 Database: {DB_PATH}")
    print(f"🌐 Server: http://0.0.0.0:5000")
    print(f"📱 Dashboard: http://localhost:5000")
    print("=" * 60)
    print("✅ Ready to analyze threats!")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
