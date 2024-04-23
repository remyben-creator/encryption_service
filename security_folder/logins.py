import json
from datetime import datetime, timedelta

try:
    with open('./security_folder/authorized_users.json', 'r') as f:
        authorized_users = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    print("Authorized users file not found or invalid. Creating a new one.")
    authorized_users = {}

def manage_login_attempts(username, success):
    now = datetime.now()
    formatted_now = now.strftime("%Y-%m-%d %H:%M:%S")
    if "locked_out" in authorized_users[username]:
        lock = datetime.strptime(authorized_users[username]["locked_out"], "%Y-%m-%d %H:%M:%S")
        if now - lock < timedelta(seconds=60):
            print("Account is locked. Please try again later.")
            exit()
    
    if "login_attempts" not in authorized_users[username]:
        authorized_users[username]["login_attempts"] = []

    if success:
        authorized_users[username]["login_attempts"].append(True)
    else:
        if all(item == False for item in authorized_users[username]["login_attempts"][-2:]):
            if "anomaly" not in authorized_users[username]:
                authorized_users[username]["anomaly"] = []

            authorized_users[username]["anomaly"].append(formatted_now)
            print("Anomaly detected. Logging incident. Account Locked for 60 seconds.")

            authorized_users[username]["locked_out"] = formatted_now

        authorized_users[username]["login_attempts"].append(False)

    with open('authorized_users.json', 'w') as f:
            json.dump(authorized_users, f)

def get_login_attempts(username):
    successes = 0
    failures = 0
    for attempt in authorized_users[username]["login_attempts"]:
        if attempt: successes += 1
        else: failures += 1
    if "anomaly" in authorized_users[username]:
        print("Anomalies detected:")
        for anomaly in authorized_users[username]["anomaly"]:
                print(anomaly)
    print(f"Login attempts for {username}:")
    print(f"Successes: {successes}")
    print(f"Failures: {failures}")