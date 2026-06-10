import sqlite3
import json
from datetime import datetime

class ScamDatabase:
    def __init__(self, db_path='scam_data.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
        print(f"[Database] Initialized: {db_path}")
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Main content table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS content (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                content_id TEXT,
                url TEXT,
                title TEXT,
                description TEXT,
                risk_level TEXT,
                risk_score REAL,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Entities table (phone, UPI, email, etc.)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                content_id INTEGER,
                platform TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1,
                FOREIGN KEY (content_id) REFERENCES content(id)
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_scanned INTEGER,
                total_flagged INTEGER,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0
            )
        ''')
        
        # Indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_content_risk 
            ON content(risk_level)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_entity_value 
            ON entities(entity_value)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_entity_type 
            ON entities(entity_type)
        ''')
        
        self.conn.commit()
    
    def save_content(self, content_list):
        """Analyzed content ko database mein save karo"""
        cursor = self.conn.cursor()
        saved_count = 0
        
        for content in content_list:
            try:
                content_id = (content.get('video_id') or 
                             content.get('post_id') or 
                             content.get('tweet_id') or 
                             content.get('url'))
                
                # Check duplicate
                cursor.execute('''
                    SELECT id FROM content 
                    WHERE source = ? AND content_id = ?
                ''', (content.get('source'), content_id))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing
                    content_db_id = existing[0]
                    cursor.execute('''
                        UPDATE content SET
                            risk_level = ?,
                            risk_score = ?
                        WHERE id = ?
                    ''', (
                        content.get('risk_analysis', {}).get('risk_level'),
                        content.get('risk_analysis', {}).get('risk_score'),
                        content_db_id
                    ))
                else:
                    # Insert new
                    cursor.execute('''
                        INSERT INTO content 
                        (source, content_id, url, title, description, risk_level, risk_score)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        content.get('source'),
                        content_id,
                        content.get('url'),
                        str(content.get('title')or'')[:500],
                        str(
                        content.get('description')
                        or content.get('caption')
                        or content.get('text')
                        or''
                        )[:1000],
                        content.get('risk_analysis', {}).get('risk_level'),
                        content.get('risk_analysis', {}).get('risk_score')
                    ))
                    content_db_id = cursor.lastrowid
                
                # Save entities
                self._save_entities(cursor, content, content_db_id)
                saved_count += 1
                
            except Exception as e:
                print(f"  [!] DB save error: {e}")
        
        self.conn.commit()
        # print(f"[Database] Saved {saved_count}/{len(content_list)} items")
        return saved_count
    
    def _save_entities(self, cursor, content, content_db_id):
        """Entities ko save/update karo"""
        entities = content.get('entities', {})
        platform = content.get('source', 'unknown')
        
        for etype, entity_list in entities.items():
            for entity in entity_list:
                if not entity:
                    continue
                
                # Check if entity already exists
                cursor.execute('''
                    SELECT id, occurrence_count FROM entities 
                    WHERE entity_value = ? AND entity_type = ?
                ''', (entity, etype))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update count and last_seen
                    entity_db_id, count = existing
                    cursor.execute('''
                        UPDATE entities SET
                            occurrence_count = ?,
                            last_seen = CURRENT_TIMESTAMP,
                            platform = ?
                        WHERE id = ?
                    ''', (count + 1, platform, entity_db_id))
                else:
                    # Insert new entity
                    cursor.execute('''
                        INSERT INTO entities 
                        (entity_value, entity_type, content_id, platform)
                        VALUES (?, ?, ?, ?)
                    ''', (entity, etype, content_db_id, platform))
    
    def save_scan_history(self, total_scanned, flagged_items):
        """Har scan ka record rakho"""
        cursor = self.conn.cursor()
        
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for item in flagged_items:
            level = item.get('risk_analysis', {}).get('risk_level', 'LOW')
            if level in risk_counts:
                risk_counts[level] += 1
        
        cursor.execute('''
            INSERT INTO scan_history 
            (total_scanned, total_flagged, critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            total_scanned,
            len(flagged_items),
            risk_counts['CRITICAL'],
            risk_counts['HIGH'],
            risk_counts['MEDIUM'],
            risk_counts['LOW']
        ))
        
        self.conn.commit()
    
    def get_statistics(self):
        """Database se statistics nikaalo"""
        cursor = self.conn.cursor()
        stats = {}
        
        # Total content
        cursor.execute("SELECT COUNT(*) FROM content")
        stats['total_content'] = cursor.fetchone()[0]
        
        # Risk distribution
        cursor.execute("""
            SELECT risk_level, COUNT(*) as cnt 
            FROM content 
            WHERE risk_level IS NOT NULL 
            GROUP BY risk_level 
            ORDER BY cnt DESC
        """)
        stats['risk_distribution'] = dict(cursor.fetchall())
        
        # Top entities
        cursor.execute("""
            SELECT entity_value, entity_type, occurrence_count 
            FROM entities 
            ORDER BY occurrence_count DESC 
            LIMIT 20
        """)
        stats['top_entities'] = [
            {'value': row[0], 'type': row[1], 'count': row[2]}
            for row in cursor.fetchall()
        ]
        
        # Platform distribution
        cursor.execute("""
            SELECT source, COUNT(*) as cnt 
            FROM content 
            GROUP BY source 
            ORDER BY cnt DESC
        """)
        stats['platform_distribution'] = dict(cursor.fetchall())
        
        # Scan history
        cursor.execute("""
            SELECT scan_time, total_scanned, total_flagged 
            FROM scan_history 
            ORDER BY scan_time DESC 
            LIMIT 10
        """)
        stats['recent_scans'] = [
            {'time': row[0], 'scanned': row[1], 'flagged': row[2]}
            for row in cursor.fetchall()
        ]
        
        # Phone numbers found
        cursor.execute("""
            SELECT COUNT(DISTINCT entity_value) 
            FROM entities 
            WHERE entity_type = 'phone_numbers'
        """)
        stats['unique_phones'] = cursor.fetchone()[0]
        
        # UPI IDs found
        cursor.execute("""
            SELECT COUNT(DISTINCT entity_value) 
            FROM entities 
            WHERE entity_type = 'upi_ids'
        """)
        stats['unique_upi'] = cursor.fetchone()[0]
        
        return stats
    
    def get_entity_details(self, entity_value):
        """Kisi specific entity ke baare mein detail nikaalo"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT e.entity_value, e.entity_type, e.occurrence_count, 
                   e.platform, e.first_seen, e.last_seen,
                   c.url, c.title, c.risk_level
            FROM entities e
            LEFT JOIN content c ON e.content_id = c.id
            WHERE e.entity_value = ?
            ORDER BY e.last_seen DESC
            LIMIT 50
        ''', (entity_value,))
        
        rows = cursor.fetchall()
        
        if not rows:
            return None
        
        return {
            'entity': rows[0][0],
            'type': rows[0][1],
            'total_occurrences': rows[0][2],
            'platforms': list(set(r[3] for r in rows if r[3])),
            'first_seen': rows[0][4],
            'last_seen': rows[0][5],
            'associated_content': [
                {'url': r[6], 'title': r[7], 'risk': r[8]}
                for r in rows if r[6]
            ]
        }
    
    def export_for_report(self):
        """Dashboard ke liye data export karo"""
        stats = self.get_statistics()
        
        # Get recent high-risk items
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT source, url, title, risk_level, risk_score, collected_at
            FROM content 
            WHERE risk_level IN ('CRITICAL', 'HIGH')
            ORDER BY collected_at DESC 
            LIMIT 50
        """)
        
        recent_high_risk = [
            {'source': r[0], 'url': r[1], 'title': r[2], 
             'risk_level': r[3], 'risk_score': r[4], 'time': r[5]}
            for r in cursor.fetchall()
        ]
                # IOC Reputation Engine
        cursor.execute("""
            SELECT entity_value, entity_type, occurrence_count
            FROM entities
            ORDER BY occurrence_count DESC
            LIMIT 50
        """)

        suspicious_iocs = []

        type_scores = {
            'phone_numbers': 25,
            'upi_ids': 35,
            'telegram_usernames': 15,
            'telegram_links': 15,
            'domains': 10,
            'btc_wallets': 50,
            'eth_wallets': 50,
            'trx_wallets': 50,
            'emails': 10,
            'urls': 5
        }

        for value, etype, count in cursor.fetchall():

            score = type_scores.get(etype, 5)

            if count >= 20:
                score += 60
            elif count >= 10:
                score += 40
            elif count >= 5:
                score += 20

            score = min(score, 100)

            if score >= 90:
                severity = "CRITICAL"
            elif score >= 70:
                severity = "HIGH"
            elif score >= 40:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            suspicious_iocs.append({
                "entity": value,
                "type": etype,
                "occurrences": count,
                "score": score,
                "severity": severity
            })

        suspicious_iocs = sorted(
            suspicious_iocs,
            key=lambda x: x["score"],
            reverse=True
        )[:20]

        return {
            'statistics': stats,
            'recent_high_risk': recent_high_risk,
            'suspicious_iocs': suspicious_iocs,
            'graph_data': self.get_graph_data()
        }
    
    def get_graph_data(self):
        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT entity_value,
                   entity_type,
                   platform
            FROM entities
            WHERE occurrence_count >= 2
            LIMIT 100
        """)
        
        return cursor.fetchall()

    def close(self):
        self.conn.close()
        print("[Database] Connection closed")
