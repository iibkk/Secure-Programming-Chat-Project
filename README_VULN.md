# Vulnerable Chat System — Assignment Submission

## Introduction
This is the intentionally vulnerable version of our secure chat project.  

Please note: this build is deliberately weakened. It must not be used in any real-world or production environment.

---

## How to Run (Vulnerable Mode)
You can enable vulnerable mode either with the `--vuln` flag or by setting an environment variable.

### Start the server
bash
python server.py --host 127.0.0.1 --port 8765

---

# Start clients (in separate terminals)
python client.py --url ws://127.0.0.1:8765 --vuln
python client.py --url ws://127.0.0.1:8765 --vuln

---

# Commands available in the client:

list = see online users
tell <user_id> <msg> = direct message
all <msg> = broadcast
quit = exit

---

# Known Vulnerabilities

Replay protection disabled: Duplicate messages are accepted.
Weakened key validation: The client and server may accept weaker RSA keys.
Other subtle flaws are left in place for reviewers to discover.

---

# Contact

Name: Chenyu Duan
Student ID: a1888643
Email: a1888643@adelaide.edu.au

----













