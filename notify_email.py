def write_log(username, user_agent):
    username = username.replace('\r', '').replace('\n', '')
    user_agent = user_agent.replace('\r', '').replace('\n', '')
    
    log_entry = {
        "username": username,
        "user_agent": user_agent
    }
    
    with open('log_file.json', 'a') as f:
        json.dump(log_entry, f)
        f.write('\n')