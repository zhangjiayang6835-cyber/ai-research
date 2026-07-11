from smtplib import SMTP
from email.mime.text import MIMEText

def send_email(subject, to_email):
    msg = MIMEText('This is the email body.')
    msg['Subject'] = subject
    msg['To'] = to_email
    
    server = SMTP('localhost')
    server.sendmail('from@example.com', [to_email], msg.as_string())
    server.quit()