import os
import sqlite3
import win32crypt
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import base64


def get_chrome_cookies() -> dict:
    user_profile = os.environ['USERPROFILE']
    cookie_path = os.path.join(user_profile, r'AppData\Local\Google\Chrome\User Data\Default\Cookies')
    shutil.copy2(cookie_path, 'Cookies_copy')
    conn = sqlite3.connect('Cookies_copy')
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    cookies = {}
    for host_key, name, encrypted_value in cursor.fetchall():
        decrypted_value = decrypt_cookie(encrypted_value)
        cookies[name] = {
            'host': host_key,
            'value': decrypted_value
        }
    conn.close()
    os.remove('Cookies_copy')
    return cookies


def check_path(path: str):
    if not os.path.exists(path):
        raise FileNotFoundError(f"ERROR: {path} not found")

def build_chrome_cipher() -> Cipher:
    CHROME_STATE = r'AppData\Local\Google\Chrome\User Data\Local State'
    user_profile = os.environ['USERPROFILE']
    check_path(user_profile, is_dir=True)
    local_path = os.path.join(user_profile, CHROME_STATE)
    with open(local_path, 'r', encoding='utf-8') as file:
        local_state = file.read()
    os_key = local_state['os_crypt']['encrypted_key']
    encrypted_key = None if not os_key or len(os_key) < 5 else os_key[5:]
    if not encrypted_key:
        raise ValueError("Failed to resolve the OS key")
    encrypted_key = base64.b64decode(os_key)
    resolved_key = win32crypt.CryptUnprotectData(
        encrypted_key, None, None, None, 0)[1]
    return Cipher(algorithms.AES(resolved_key), modes.GCM(encrypted_key[3:15]))


def decrypt_cookie(encrypted_value) -> str:
    try:
        cipher = build_chrome_cipher()
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(
            encrypted_value[15:-16]) + decryptor.finalize()
        return decrypted.decode()
    except Exception as e:
        try:
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_value, None, None, None, 0)
            return decrypted[1].decode()
        except:
            return ""


def get_lines(file) -> set:
    domains = set()
    for line in file:
        stripped = line.strip()
        if not stripped or line.startswith('#'):
            continue
        domains.add(stripped)
    return domains


def load_tracking_domains(file_path):
    with open(file_path, 'r') as f:
        domains = get_lines(f)
    return domains


def identify_tracking_cookies(cookies: dict, tracking_domains) -> dict:
    tracking_cookies = {}
    for name, details in cookies.items():
        domain = details['host']
        if any(domain.endswith(tracking_domain) for tracking_domain in tracking_domains):
            tracking_cookies[name] = details
    return tracking_cookies


def main() -> None:
    DOMAIN_FILE = 'tracking_domains.txt'
    cookies = get_chrome_cookies()

    # tracking_domains = load_tracking_domains(DOMAIN_FILE)

    # tracking_cookies = identify_tracking_cookies(cookies, tracking_domains)

    # print("Tracking Cookies:")
    for name, details in cookies.items():
        print(f"""
Cookie Name: {name}
Host: {details['host']}
Value: {details['value']}
              """)
        print("*" * 50)

if __name__ == "__main__":
    main()