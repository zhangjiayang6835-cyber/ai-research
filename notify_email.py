def write_log(log_message, username, user_agent):
    # Remove or escape CRLF characters
    log_message = log_message.replace('\r', '').replace('\n', '\\n')
    username = username.replace('\r', '').replace('\n', '\\n')
    user_agent = user_agent.replace('\r', '').replace('\n', '\\n')

    # Ensure the log message is in JSON format
    log_entry = {
        "message": log_message,
        "username": username,
        "user_agent": user_agent
    }

    import json
    log_str = json.dumps(log_entry)

    # Write the structured log to file
    with open('log_file.log', 'a') as f:
        f.write(f"{log_str}\n")