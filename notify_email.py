from smtplib import SMTP
from email.mime.text import MIMEText

def send_email(subject, recipient):
    msg = MIMEText('This is the email body.')
    msg['Subject'] = subject
    msg['To'] = recipient
    
    with SMTP('localhost') as server:
        server.sendmail('sender@example.com', [recipient], msg.as_string())