def export_comments_to_csv(user_ids):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            query = "SELECT * FROM comments WHERE id IN (%s)"
            cursor.execute(query, (user_ids,))
            results = cursor.fetchall()
            # Further code to write results to CSV