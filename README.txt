Secure Chat Protocol – Week 9 Submission (RUN GUIDE)

#####
Repository layout
- server.py               : WebSocket relay
- client.py               : CLI client
- config.py               : shared settings (modes / limits)
- modules/crypto_rsa.py   : crypto helpers (RSA, base64url, canon JSON)
- modules/formats.py      : message envelope/payload helpers
- docs/protocol.md        : message shapes (for reference)
- README.txt              : how to run guide


#####
Requirements
- Python 3.11+ (recommended)
- pip (Python package installer)


#####
Python packages used by this project:
- websockets
- cryptography
(pip will also pull cffi and pycparser automatically as needed)

manual install:
pip install websockets cryptography


#####
Install (Windows / PowerShell):
(1) Open PowerShell in the project folder.
(2) (One terminal at a time) allow activation in this shell:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
(3) Create and activate venv:
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
(4) Install dependencies:
    pip install websockets
    pip install cryptography
(5) Quick self-test (optional):
    python -m modules.crypto_rsa
    (Expected: "[crypto_rsa] self-test OK")

Install (macOS/Linux)
(1) cd into the project folder.
(2) python3 -m venv .venv
(3) source .venv/bin/activate
(4) pip install websockets
(5) pip install cryptography
(5) python -m modules.crypto_rsa


#####
Starting the server (local machine)
in .venv mode repeat this step: 
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

- Clean mode:
    python server.py --host 127.0.0.1 --port 8765

- Review mode:
    python server.py --vuln --host 127.0.0.1 --port 8765

You should see:
    [server] <uuid> ws://127.0.0.1:8765

#####
Starting clients (separate terminals)
Open TWO new terminals and activate the venv in each:
    Windows:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
        .\.venv\Scripts\Activate.ps1
    macOS/Linux:
        source .\.venv\Scripts\Activate.ps1

Client A:
    python client.py --url ws://127.0.0.1:8765
    (optionally) python client.py --vuln --url ws://127.0.0.1:8765

Client B (different identity on the same PC):
    Before starting B, do this while Client A is running:
        Delete the current user ID file so a fresh one is created:
        Windows:
            $dir = "$env:USERPROFILE\.yourchat\client"
            Remove-Item "$dir\user_id.txt" -Force -ErrorAction SilentlyContinue
        macOS/Linux:
            rm -f ~/.yourchat/client/user_id.txt

    Then start Client B:
        python client.py --url ws://127.0.0.1:8765
        (optionally) python client.py --vuln --url ws://127.0.0.1:8765


#####
To run this on 2 different computers on different WIFI's please see bottom of this txt on how to go about it


#####
Client commands
- list
- tell <user_uuid> <text>
- all <text>
- quit


#####
Minimal test (two terminals running clients)
(1) In Client A:  list
        Expect to see both user IDs once B has connected.
(2) In Client A:  tell <B_uuid> hello
        Expect Client B to print: [dm <A8>→you] hello
(3) In Client A or B:  all hi everyone
        Expect the other client to print the message.

#####
Troubleshooting
- “only one usage of each socket address / port 8765 is in use”:
    Another server is already running. Stop it with Ctrl+C or use a new port:
        python server.py --host 127.0.0.1 --port 8888
    Clients connect with:
        python client.py --url ws://127.0.0.1:8888

- PowerShell says activation scripts are blocked:
    Run this in each new terminal before activating venv:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

- Client says “unknown user; run 'list'”:
    The recipient hasn’t connected yet or your directory is stale.
    Run: list   (after the other client connects) and retry.

- Both clients appear as the same user (same UUID):
    On one PC, delete ~/.yourchat/client/user_id.txt before starting the
    second client (see instructions above).

- Dependencies missing:
    Make sure venv is active, then:
    pip install websockets
    pip install cryptography

#####
Expected folder layout to run
project/
    server.py
    client.py
    config.py
    docs/
         protocol.md
   modules/
         __init__.py
        crypto_rsa.py
         formats.py

#####
How to run over two different computers on different WIFI's using Radmin VPN to bypass port forwarding:
(1) Install Radmin VPN on both PCs.
    Open Radmin VPN - Network - “Join an existing network or Create one”
    Network name: xxxxx
    Password: xxxxx
    Once joined, you’ll see a 26.x.x.x “Radmin IP” next to each PC.

(2) Choose which PC will run the server.
    On that PC, note the Radmin IP (e.g., 26.50.200.220). This is the address clients will use.

(3) On the server PC, open PowerShell in the project folder and start the server bound to the Radmin IP:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\.venv\Scripts\Activate.ps1
    python server.py --host 26.50.200.220 --port 8765
    (If you prefer to listen on all interfaces, you can use --host 0.0.0.0, but clients should still connect to the server’s Radmin IP.)

You should see:
[server] <uuid> ws://26.50.200.220:8765

Firewall tip (only needed if clients cannot connect):
- Allow inbound TCP 8765 on the server PC:
- netsh advfirewall firewall add rule name="yourchat-ws-8765" dir=in action=allow protocol=TCP localport=8765

NOTE: if a user is using an antivirus application like "Norton" it will need to be disabled or radmivpn will need to be excluded for radmivpn to properly work.

(4) On each client PC (which can include the server PC itself), open PowerShell in the project folder and start a client pointing to the server’s Radmin IP:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\.venv\Scripts\Activate.ps1
    python client.py --url ws://26.50.200.220:8765

    If you run a client on the same PC as the server AND another client on a second PC, make sure the two clients have different user IDs:
        Start the first client.
        Before starting a second client on the same PC, delete the local ID file:
            -  $dir = "$env:USERPROFILE\.yourchat\client"
            -  Remove-Item "$dir\user_id.txt" -Force -ErrorAction SilentlyContinue
        Then start the second client in a new terminal.

You should see something like:
[you] user_id=<UUID>
commands: list | tell <user_uuid> <text> | all <text> | quit

(5) Test:
    In Client A: list
    In Client B: list
    (You should see each other’s UUIDs.)
    In Client A: tell <B_uuid> hello
    (Client B should print the message.)
    Optionally try: all hi everyone

(6) Notes & tips:
    The server’s IP in the client URL must be the server PC’s Radmin IP.
    If port 8765 is already in use, pick another (e.g., 8081) on both sides:
    Server: python server.py --host 26.50.200.220 --port 8081
    Client: python client.py --url ws://26.50.200.220:8081
    If “list” shows only one user, wait until the other client connects, then run “list” again.
    If a client runs on the same PC as the server, it should still connect using the Radmin IP (not 127.0.0.1) if the server only bound to that Radmin address.

(7) Troubleshooting:
If the server says the port is in use, pick another port on BOTH sides:
    Server:  python server.py --host 26.50.200.220 --port 8081
    Client:  python client.py --url ws://26.50.200.220:8081
If clients can’t connect:
    Confirm both PCs show as “online” in the same Radmin network.
    Use `ping 26.50.200.220` from the client PC to check reachability.
    Recheck Windows Firewall/Antivirus exceptions for Python and Radmin VPN.


#####
Contact
- Chenyu Duan - a1888643@adelaide.edu.au
- Luan Kafexholli -a1884136@adelaide.edu.au
- Gian Henley Willemse - a1897502@adelaide.edu.au
- Ibunkun Oluwajomiloju Adeoye - a1877853@adelaide.edu.au
- Jordan Riley Czyzowski - a1853138@adelaide.edu.au