#CARINGCARIBOU SEED REQUEST
#caringcaribou -i <interface> uds security_seed -r <reset_type> -n <seeds_to_capture> <session_type> <session_security> <txid> <rxid>

import subprocess
from pathlib import Path
import sqlite3
import re
CURRENT_DIR = Path(__file__).resolve().parent
LOG_FILE_PATH = CURRENT_DIR / "logs/seeds.txt"
DB_PATH = CURRENT_DIR / "logs/uds_seeds.db"
LOG_FILE_PATH_DIAGNOSTIC = CURRENT_DIR / "logs/diagnostic.txt"

def init_db():
    """Create DB to save the obtained seeds"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS seed_key_pairs (
                seed TEXT PRIMARY KEY,
                associated_key TEXT DEFAULT NULL,
                counter INTEGER DEFAULT 1
            )
        """)
        conn.commit()

def save_seed_to_db(seed_value):
    """Insert seed in DB or update counter"""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO seed_key_pairs (seed, associated_key, counter)
            VALUES (?, NULL, 1)
            ON CONFLICT(seed) DO UPDATE SET counter = counter + 1
        """, (seed_value,))
        conn.commit()

def seed_request_debug(rtype, to_capture, session_type_str, session_security_str, txid_hex, rxid_hex, interface="can0"):
    """Capture seed, write log on screen and in DB"""
    init_db()  # initialize DB
    #caringcaribou command
    cmd = [
        'caringcaribou', '-i', interface, 
        'uds', 'security_seed', 
        '-r', str(rtype), 
        '-n', str(to_capture), 
        session_type_str, session_security_str, 
        txid_hex, rxid_hex
    ]
            
    with open(LOG_FILE_PATH, "w") as f:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )    
        for line in iter(process.stdout.readline, ""):
            print(line, end="")  # print on screen
            f.write(line)        # write on log file for persistence
            f.flush()
            #REGEX to extract seed from the print
            match = re.search(r'Seed received:\s+([0-9a-fA-F]+)', line)
            if match:
                extracted_seed = match.group(1).strip().lower()
                if extracted_seed:
                    save_seed_to_db(extracted_seed)
        process.stdout.close()
        process.wait()
    return process.returncode

if __name__ == "__main__": 
    interface = "can0"
    to_capture = 3000 # number of seed request
    rtype = 1 #1--> hard reset, 3-->soft reset
    session_type = 0x02 #programming session
    session_security = 0x01 #security level
    f=open(LOG_FILE_PATH_DIAGNOSTIC,"r")
    line = f.readline()
    # Convert numeric values to hexadecimal strings where needed
    session_type_str = str(session_type)
    session_security_str = str(session_security)
    txid_hex = hex(int(line.split(" ")[0], 16))
    rxid_hex = hex(int(line.split(" ")[1], 16))
    result = seed_request_debug(rtype, to_capture, session_type_str, session_security_str, txid_hex, rxid_hex, interface)