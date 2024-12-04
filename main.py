import os
import json
import base64
import shutil
import requests
import tempfile
import zipfile
import sys
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'


class PluginVerifier:
    def __init__(self, official_key: str):
        self.official_key = official_key
        self.public_keys = {}

    def normalize_content(self, content: str) -> str:
        """標準化內容的換行符"""
        return content.replace('\r\n', '\n').replace('\r', '\n')

    def get_all_files(self, directory: str, base_dir: str = None) -> Dict[str, str]:
        """獲取目錄下所有文件的內容"""
        if base_dir is None:
            base_dir = directory

        results = {}
        for item in os.listdir(directory):
            if item.startswith('.') or item == 'signature.json':
                continue

            full_path = os.path.join(directory, item)
            if os.path.isdir(full_path):
                results.update(self.get_all_files(full_path, base_dir))
            else:
                rel_path = os.path.relpath(
                    full_path, base_dir).replace('\\', '/')
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = self.normalize_content(f.read())
                    results[rel_path] = content

        return results

    def verify(self, plugin_dir: str) -> Dict[str, Any]:
        """驗證插件"""
        try:
            signature_path = os.path.join(plugin_dir, 'signature.json')
            if not os.path.exists(signature_path):
                return {"valid": False, "error": "Missing signature.json"}

            with open(signature_path, 'r', encoding='utf-8') as f:
                signature_data = json.load(f)
                print(f"{Colors.YELLOW}Signature data loaded:{Colors.RESET}")
                print(json.dumps(signature_data, indent=2))

            file_hashes = signature_data.get('fileHashes')
            signature = signature_data.get('signature')
            key_id = signature_data.get('keyId')

            if not file_hashes or not signature:
                return {"valid": False, "error": "Invalid signature data format"}

            print(f"\n{Colors.BLUE}Verifying files...{Colors.RESET}")
            all_files = self.get_all_files(plugin_dir)
            print(f"Found {len(all_files)} files to verify:")
            for file_path in sorted(all_files.keys()):
                print(f"  {file_path}")

            print(f"\n{Colors.BLUE}Checking file hashes...{Colors.RESET}")
            for file_path, content in all_files.items():
                if file_path == 'trem.json':
                    continue

                if file_path not in file_hashes:
                    return {"valid": False, "error": f"Extra file: {file_path}"}

                actual_hash = hashes.Hash(hashes.SHA256())
                actual_hash.update(content.encode())
                actual_hash_hex = actual_hash.finalize().hex()

                print(f"File: {file_path}")
                print(f"  Expected: {file_hashes[file_path]}")
                print(f"  Actual:   {actual_hash_hex}")

                if actual_hash_hex != file_hashes[file_path]:
                    return {"valid": False, "error": f"Modified file: {file_path}"}

            print(f"\n{Colors.BLUE}Verifying signature...{Colors.RESET}")
            print(f"Using key ID: {key_id or 'official'}")

            message = json.dumps(file_hashes, sort_keys=True,
                                 separators=(',', ':')).encode()
            signature_bytes = base64.b64decode(signature)

            print(f"Message length: {len(message)} bytes")
            print(f"Signature length: {len(signature_bytes)} bytes")
            print(f"Message (first 100 bytes): {message[:100]}...")

            public_key_obj = load_pem_public_key(self.official_key.encode())
            public_key_obj.verify(
                signature_bytes,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return {
                "valid": True,
                "error": None,
                "keyId": key_id or 'official'
            }
        except InvalidSignature:
            # 嘗試不同的序列化方式
            print(
                f"{Colors.YELLOW}First attempt failed, trying alternative serialization...{Colors.RESET}")
            message = json.dumps(file_hashes, separators=(',', ':')).encode()
            try:
                public_key_obj.verify(
                    signature_bytes,
                    message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return {
                    "valid": True,
                    "error": None,
                    "keyId": key_id or 'official'
                }
            except InvalidSignature:
                print(f"{Colors.RED}Signature verification details:{Colors.RESET}")
                print("- File hashes match but signature is invalid")
                print("- This could mean:")
                print("  1. The signature was created with a different private key")
                print("  2. The file hash data was serialized differently")
                print("  3. The signature was generated with different parameters")
                return {
                    "valid": False,
                    "error": "Invalid signature",
                    "keyId": key_id or 'official'
                }

        except Exception as e:
            print(f"{Colors.RED}Verification error: {str(e)}{Colors.RESET}")
            return {"valid": False, "error": str(e)}


def download_and_verify_plugin(org: str, repo: str, plugin_name: str, verifier: PluginVerifier):
    """下載並驗證插件"""
    print(f"{Colors.BLUE}Downloading latest release from {org}/{repo}...{Colors.RESET}")

    try:
        # 獲取最新release
        api_url = f"https://api.github.com/repos/{org}/{repo}/releases/latest"
        response = requests.get(api_url)
        response.raise_for_status()
        release_data = response.json()

        # 下載插件
        trem_file = f"{plugin_name}.trem"
        asset_url = None
        for asset in release_data["assets"]:
            if asset["name"] == trem_file:
                asset_url = asset["browser_download_url"]
                break

        if not asset_url:
            raise ValueError(f"Could not find {trem_file} in latest release")

        # 下載並解壓
        response = requests.get(asset_url)
        response.raise_for_status()

        temp_dir = tempfile.mkdtemp()
        trem_path = os.path.join(temp_dir, trem_file)

        with open(trem_path, "wb") as f:
            f.write(response.content)

        print(f"{Colors.GREEN}Downloaded {trem_file}{Colors.RESET}")

        # 解壓縮
        plugin_dir = os.path.join(temp_dir, "plugin")
        os.makedirs(plugin_dir, exist_ok=True)

        with zipfile.ZipFile(trem_path, 'r') as zip_ref:
            zip_ref.extractall(plugin_dir)

        # 驗證
        result = verifier.verify(plugin_dir)

        if result["valid"]:
            print(f"{Colors.GREEN}Plugin verification successful!{Colors.RESET}")
        else:
            print(
                f"{Colors.RED}Plugin verification failed: {result['error']}{Colors.RESET}")

        # 清理臨時文件
        shutil.rmtree(temp_dir)

        return result

    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        return {"valid": False, "error": str(e)}


# 使用示例
if __name__ == "__main__":
    public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzQn1ouv0mfzVKJevJiq+
6rV9mwCEvQpauQ2QNjy4TiwhqzqNiOPwpM3qo+8+3Ld+DUhzZzSzyx894dmJGlWQ
wNss9Vs5/gnuvn6PurNXC42wkxY6Dmsnp/M6g08iqGXVcM6ZWmvCZ3BzBvwExxRR
09KxHZVhwoMcF5Kp9l/hNZqXRgYMn3GLt+m78Hr+ZUjHiF8K9UH2TPxKRa/4ttPX
6nDBZxZUCwFD7Zh6RePg07JDbO5fI/UYrqZYyDPK8w9xdXtke9LbdXmMuuk/x57h
foRArUkhPvUk/77mxo4++3EFnTUxYMnQVuMkDaYNRu7w83abUuhsjNlL/es24HSm
lwIDAQAB
-----END PUBLIC KEY-----'''

    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <org> <repo> <plugin_name>")
        sys.exit(1)

    verifier = PluginVerifier(public_key)
    download_and_verify_plugin(sys.argv[1], sys.argv[2], sys.argv[3], verifier)
