from agents.red_team import run_red_team

vulnerable_code = """
import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
"""

vulnerable_code = """
import os

def read_file(filename):
    path = "/var/data/" + filename
    with open(path, 'r') as f:
        return f.read()
"""

findings = run_red_team(vulnerable_code)
for f in findings:
    print(f.finding_id, f.cwe_id, f.severity)
    print(f.exploit_argument)
    print("---")