import csv
from flask import send_file

def export_messages_to_csv():
    # Fetch all messages from the database using parameterized queries
    cursor.execute("SELECT id, content FROM messages")
    messages = cursor.fetchall()

    # Prepare the CSV content
    csv_filename ='messages.csv'
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['id','message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for message in messages:
            # Use the csv module to write the data, which handles escaping
            writer.writerow({'id': message['id'],'message': message['content']})

    # Export the CSV file to the user
    return send_file(csv_filename, as_attachment=True)

# Example usage in a Flask route
from flask import Flask
app = Flask(__name__)

@app.route('/export_messages')
def export_messages_route():
    return export_messages_to_csv()

if __name__ == '__main__':
    app.run(debug=True)