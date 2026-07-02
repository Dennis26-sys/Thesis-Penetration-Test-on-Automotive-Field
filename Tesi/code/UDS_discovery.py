#CARINGCARIBOU DISCOVERY
import subprocess
from pathlib import Path
import can
import time

CURRENT_DIR = Path(__file__).resolve().parent
LOG_FILE_PATH = CURRENT_DIR / "logs/discovery_output.txt"
LOG_FILE_PATH_DIAGNOSTIC = CURRENT_DIR / "logs/diagnostic.txt"
#caringcaribou -i <interface> uds discovery -min <min_value> -max <max_value>

def verifica_coppia_diagnostica(client_id, server_id, interface="can0"):
    """
    send UDS DiagnosticSessionControl (10 01) to verify 
    if the couple CLIENT/SERVER is diagnostic related or false positive.
    """
    is_extended = client_id > 0x7FF or server_id > 0x7FF
    can_mask = 0x1FFFFFFF if is_extended else 0x7FF
    can_filters = [{"can_id": server_id, "can_mask": can_mask, "extended": is_extended}]
    SERVICE = 0x10
    SUBFUNCTION = 0x01
    try:
        bus = can.interface.Bus(channel=interface, interface="socketcan", can_filters=can_filters)
        # Standard Payload Single Frame UDS (0x02 bytes, Service 0x10, Subfunction 0x01)
        payload = [0x02, SERVICE, SUBFUNCTION, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]
        msg = can.Message(
            arbitration_id=client_id,
            data=payload,
            is_extended_id=is_extended
        )
        bus.send(msg)
        start_time = time.time()
        while (time.time() - start_time) < 0.15:
            rx_msg = bus.recv(timeout=0.05)
            if rx_msg and rx_msg.arbitration_id == server_id:
                # If ECU responds with positive response (0x50) to service 0x10
                #single frame
                if len(rx_msg.data) >= 3 and rx_msg.data[1] == (SERVICE + 0x40) and rx_msg.data[2] == SUBFUNCTION:
                    bus.shutdown()  
                    return True
                #first frame
                if len(rx_msg.data) >= 4 and ((rx_msg.data[0] & 0xF0) >> 4) == 0x01 and rx_msg.data[2] == (SERVICE + 0x40) and rx_msg.data[3] == SUBFUNCTION:
                    bus.shutdown()  
                    return True
        bus.shutdown()
    except Exception as e:
        print(f"\n[!] Errore durante il test hardware della coppia: {e}")
    return False

def run_discovery(min_value, max_value, interface="can0"):
    """
    Discovery using caringcaribou.
    """
    coppie_candidate = []
    discovered_diagnostics = []
    
    # Strings to saveCaring Caribou log
    stderr_log = ""
    print("[*] Caring Caribou loading...")
    # Ask Linux to use caringcaribou
    process = subprocess.Popen(
        ['caringcaribou', '-i', interface, "uds", "discovery", "-min", str(min_value), "-max", str(max_value)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True  
    )
    
    # Capture standard output
    for stdout_line in iter(process.stdout.readline, ""):
        print(stdout_line, end="")  # Show original output
        if "0x" in stdout_line and "|" in stdout_line:
            parti = stdout_line.split("|")
            if len(parti) >= 3:
                client_str = parti[1].strip()
                server_str = parti[2].strip()
                try:
                    client_id = int(client_str, 16)
                    server_id = int(server_str, 16)
                    if (client_id, server_id) not in coppie_candidate:
                        coppie_candidate.append((client_id, server_id))
                except ValueError:
                    continue

    # Check for false positives
    print(f"\n[*] Found {len(coppie_candidate)} couples. Validation...")
    
    for client_id, server_id in coppie_candidate:
        print(f"    [-] Test Client: 0x{client_id:08X} -> Server: 0x{server_id:08X} ... ", end="", flush=True)
        if verifica_coppia_diagnostica(client_id, server_id, interface):
            print("VALID)")
            discovered_diagnostics.append((client_id, server_id))
        else:
            print("False Positive")

    # Print on screen
    print(f"| {'CLIENT ID':<12} | {'SERVER ID':<12} |")
    print("-"*31)
    for c_id, s_id in discovered_diagnostics:
        print(f"| 0x{c_id:08x}   | 0x{s_id:08x}   |")
    print("="*31)

    # Print on file log
    try:
        with open(LOG_FILE_PATH, "w") as f:
            f.write(f"| {'CLIENT ID':<12} | {'SERVER ID':<12} |\n")
            for c_id, s_id in discovered_diagnostics:
                f.write(f"| 0x{c_id:08x} | 0x{s_id:08x} |\n")
    except Exception as e:
        print(f"[ERR] Errore during save: {e}")
    return discovered_diagnostics

if __name__ == "__main__":
    #discovery brute force
    min_value = 0x00000000 
    max_value = 0xFFFFFFFF 
    result = run_discovery(min_value=min_value, max_value=max_value, interface=interface)
    with open(LOG_FILE_PATH_DIAGNOSTIC, "a") as f:
        for client_id, server_id in result:
            f.write(f"{hex(client_id)} {hex(server_id)}\n")
