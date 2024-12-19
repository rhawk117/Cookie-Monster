import os
import sqlite3
import shutil
import json
import base64
import win32crypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import argparse
from colorama import Fore, Style, init

init(autoreset=True)
class Prompts:
    @staticmethod
    def color_msg(message, color) -> None:
        return color + message + Style.RESET_ALL
    
    
    @staticmethod
    def success(message) -> None:
        print(Prompts.color_msg(f'[+] {message} [+]', Fore.GREEN))

    @staticmethod
    def error(message) -> None:
        print(Prompts.color_msg(f'[-] {message} [-]', Fore.RED))

    @staticmethod
    def info(message) -> None:
        print(Prompts.color_msg(f'[*] {message} [*]', Fore.BLUE))
    

class CookieParser:
    def __init__(self, browser_type: str, cookies_path: str) -> None:
        self.browser_type: str = browser_type.lower()
        self.cookies_path = cookies_path
        self.cookies: dict = {}
        self.tracking_cookies: dict = {}
        self.tracking_domains: set = set()

    @staticmethod
    def browser_error(type: str):
        err_msg = f"Unknown / Unsupported browser '{type}'\nSupported browsers: chrome, brave, edge, firefox."
        raise ValueError(Prompts.error(err_msg))

    
    def extract_cookies(self):
        match self.browser_type:
            case 'chrome', 'edge', 'brave':
                self.cookies = self._extract_chromium_cookies()
            case 'firefox':
                self.cookies = self._extract_firefox_cookies()
            case _:
                CookieParser.browser_error(self.browser_type)        

    def decrypt_cookies(self) -> None:
        match self.browser_type:
            case 'chrome', 'edge', 'brave':
                self.cookies = self._decrypt_chromium_cookies()
            case 'firefox':
                self.cookies = self._decrypt_firefox_cookies()
            case _:
                CookieParser.browser_error(self.browser_type)

    def load_tracking_domains(self, tracking_domains_file):
        with open(tracking_domains_file, 'r') as f:
            self.tracking_domains = set(
                line.strip() for line in f if line.strip() and not line.startswith('#')
            )

    def identify_tracking_cookies(self):
        self.tracking_cookies = {}
        for name, details in self.cookies.items():
            domain = details['host']
            if any(domain.endswith(tracking_domain) for tracking_domain in self.tracking_domains):
                self.tracking_cookies[name] = details

    def get_all_cookies(self):
        return self.cookies

    def get_tracking_cookies(self):

        return self.tracking_cookies

    def _extract_chromium_cookies(self):
        temp_cookies = 'Cookies_copy'
        shutil.copy2(self.cookies_path, temp_cookies)
        conn = sqlite3.connect(temp_cookies)
        cursor = conn.cursor()
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        cookies = {}
        for host_key, name, encrypted_value in cursor.fetchall():
            cookies[name] = {
                'host': host_key,
                'encrypted_value': encrypted_value
            }
        conn.close()
        os.remove(temp_cookies)
        return cookies

    def _decrypt_chromium_cookies(self):
        decrypted_cookies = {}
        for name, details in self.cookies.items():
            encrypted_value = details['encrypted_value']
            decrypted_value = self._decrypt_chromium_value(encrypted_value)
            decrypted_cookies[name] = {
                'host': details['host'],
                'value': decrypted_value
            }
        return decrypted_cookies

    def _decrypt_chromium_value(self, encrypted_value):
        try:
            if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:]
                local_state_path = os.path.join(
                    os.environ['USERPROFILE'], 
                    r'AppData\Local\Google\Chrome\User Data\Local State'
                )
                with open(local_state_path, 'r', encoding='utf-8') as f:
                    local_state = json.loads(f.read())
                encrypted_key = base64.b64decode(
                    local_state['os_crypt']['encrypted_key'])
                if encrypted_key[:5] == b'DPAPI':
                    encrypted_key = encrypted_key[5:]
                key = win32crypt.CryptUnprotectData(
                    encrypted_key, None, None, None, 0)[1]
                cipher = Cipher(
                    algorithms.AES(key), 
                    modes.GCM(nonce), 
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                return decrypted.decode()
            else:
                decrypted = win32crypt.CryptUnprotectData(
                    encrypted_value, None, None, None, 0)
                return decrypted[1].decode()
        except Exception as e:
            Prompts.error(f"Failed to decrypt Chromium cookie: {e}")
            return ""

    def _extract_firefox_cookies(self):
        temp_cookies = 'cookies_copy.sqlite'
        shutil.copy2(self.cookies_path, temp_cookies)
        conn = sqlite3.connect(temp_cookies)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT host, name, value, encryptedValue FROM moz_cookies"
        )
        cookies = {}
        for host, name, value, encrypted_value in cursor.fetchall():
            cookies[name] = {
                'host': host,
                'value': value,  
                'encrypted_value': encrypted_value  
            }
        conn.close()
        os.remove(temp_cookies)
        return cookies

    def _decrypt_firefox_cookies(self):
        decrypted_cookies = {}
        profile_path = os.path.dirname(os.path.dirname(self.cookies_path))
        key_db_path = os.path.join(profile_path, 'key4.db')
        import subprocess
        for name, details in self.cookies.items():
            if details['value']:
                decrypted_cookies[name] = {
                    'host': details['host'],
                    'value': details['value']
                }
                continue
            decrypted_value = self._decrypt_firefox_value(
                details['encrypted_value'], profile_path)
            decrypted_cookies[name] = {
                'host': details['host'],
                'value': decrypted_value
            }
        return decrypted_cookies

    def _decrypt_firefox_value(self, encrypted_value, profile_path):
        try:
            from cryptography.hazmat.primitives.ciphers import algorithms
            return "<decrypted_value>"
        except Exception as e:
            print(f"Failed to decrypt Firefox cookie: {e}")
            return ""


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description='Extract and identify tracking cookies from browsers.')
    parser.add_argument('--browser', type=str, required=True,
                        help='Browser type: chrome, edge, brave, firefox')
    parser.add_argument('--cookies_path', type=str,
                        required=True, help='Path to the cookies file')
    parser.add_argument('--tracking_domains', type=str,
                        required=True, help='Path to tracking domains list file')

    args = parser.parse_args()

    bc = CookieParser(args.browser, args.cookies_path)

    bc.extract_cookies()

    bc.decrypt_cookies()

    bc.load_tracking_domains(args.tracking_domains)

    bc.identify_tracking_cookies()

    print("All Cookies:")
    for name, details in bc.get_all_cookies().items():
        print(f"Name: {name}, Host: {details['host']}, Value: {
              details.get('value', '')}")
    print("\nTracking Cookies:")
    for name, details in bc.get_tracking_cookies().items():
        print(f"Name: {name}, Host: {details['host']}, Value: {
              details.get('value', '')}")
