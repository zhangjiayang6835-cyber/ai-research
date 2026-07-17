import sqlite3
import csv
import io
from flask import Flask, request, jsonify, send_file
from contextlib import contextmanager
import html

app = Flask(__name__)
DATABASE = 'messages.db'

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with proper schema"""
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

@app.route('/api/messages', methods=['POST'])
def create_message():
    """Create a new message with proper parameterized query"""
    data = request.get_json()
    username = data.get('username', '')
    message = data.get('message', '')
    
    if not username or not message:
        return jsonify({'error': 'Username and message are required'}), 400
    
    # Sanitize input to prevent XSS
    username = html.escape(username)
    message = html.escape(message)
    
    with get_db() as conn:
        # Use parameterized query to prevent SQL injection
        conn.execute(
            'INSERT INTO messages (username, message) VALUES (?, ?)',
            (username, message)
        )
        conn.commit()
    
    return jsonify({'status': 'success', 'message': 'Message saved'}), 201

@app.route('/api/messages', methods=['GET'])
def get_messages():
    """Retrieve all messages safely"""
    with get_db() as conn:
        cursor = conn.execute('SELECT id, username, message, created_at FROM messages ORDER BY created_at DESC')
        messages = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({'messages': messages}), 200

@app.route('/api/admin/export-csv', methods=['GET'])
def export_messages_csv():
    """Export all messages to CSV - FIXED: No SQL injection via parameterized query"""
    try:
        with get_db() as conn:
            # FIXED: Use parameterized query instead of string concatenation
            # Previous vulnerable code would have been:
            # query = f"SELECT * FROM messages WHERE status = '{status}'"  # VULNERABLE
            
            # Secure approach: Use parameterized queries for ALL database operations
            cursor = conn.execute(
                'SELECT id, username, message, created_at FROM messages ORDER BY created_at DESC'
            )
            
            # Create CSV in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['ID', 'Username', 'Message', 'Created At'])
            
            # Write data rows - data is already safely retrieved via parameterized query
            for row in cursor.fetchall():
                # Additional CSV injection protection: escape fields that start with special chars
                message = str(row[2])
                # Prevent CSV injection by prefixing dangerous characters
                if message and message[0] in ['=', '+', '-', '@', '\t', '\r']:
                    message = "'" + message
                
                writer.writerow([
                    row[0],  # id
                    row[1],  # username
                    message,  # message (sanitized)
                    row[3]   # created_at
                ])
            
            # Prepare file for download
            output.seek(0)
            return send_file(
                io.BytesIO(output.getvalue().encode('utf-8')),
                mimetype='text/csv',
                as_attachment=True,
                download_name='messages_export.csv'
            )
    
    except Exception as e:
        app.logger.error(f'Error exporting CSV: {str(e)}')
        return jsonify({'error': 'Failed to export messages'}), 500

@app.route('/api/admin/search', methods=['GET'])
def search_messages():
    """Search messages safely with parameterized queries"""
    search_term = request.args.get('q', '')
    
    with get_db() as conn:
        # SECURE: Use parameterized query with LIKE
        cursor = conn.execute(
            'SELECT id, username, message, created_at FROM messages WHERE message LIKE ? OR username LIKE ? ORDER BY created_at DESC',
            (f'%{search_term}%', f'%{search_term}%')
        )
        results = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({'results': results}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)