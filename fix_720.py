```python
import sqlite3
from sqlite3 import Error

def create_connection(db_file):
    """ Create a database connection to the SQLite database specified by db_file """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn

def get_comments(conn, user_ids):
    """
    Get comments with parameterized query to prevent SQL injection.
    :param conn: Connection object
    :param user_ids: List of user IDs
    :return: Cursor object containing the result set
    """
    cur = conn.cursor()
    placeholders = ', '.join('?' for _ in user_ids)
    sql = f"SELECT * FROM comments WHERE id IN ({placeholders})"
    cur.execute(sql, user_ids)
    return cur.fetchall()

def main():
    database = "./comments.db"

    # Create a connection to the SQLite database
    conn = create_connection(database)
    
    if conn is not None:
        try:
            # Simulate user_ids from XSS data
            user_ids = [1, 2, '"; DROP TABLE comments; -- ', 4]
            
            # Retrieve and print comments with parameterized query
            comments = get_comments(conn, user_ids)
            for comment in comments:
                print(comment)
        except Error as e:
            print(e)
    else:
        print("Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()
```