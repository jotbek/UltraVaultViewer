import subprocess
import json
import os
import sys

# Configuration
MOUNT = "secret"
VAULT_ADDR = ""
VAULT_NAMESPACE = ""
VAULT_ROLE = ""
VAULT_CERT_PATH = (
)

def initialize():
    """
    Authenticate to Vault using a client certificate and set the VAULT_TOKEN
    environment variable for subsequent CLI commands.
    """
    # Set Vault connection environment variables
    os.environ.update({
        "VAULT_ADDR": VAULT_ADDR,
        "VAULT_NAMESPACE": VAULT_NAMESPACE,
    })

    # PowerShell script to log in with a client certificate and retrieve the token
    ps_login = f'''
    $response = Invoke-RestMethod -Uri "{VAULT_ADDR}/v1/auth/cert/login" `
        -Method Post `
        -Body @{{ "name" = "{VAULT_ROLE}" }} `
        -Headers @{{ "X-Vault-Namespace" = "{VAULT_NAMESPACE}" }} `
        -Certificate (Get-PfxCertificate "{VAULT_CERT_PATH}")
    # Output only the client_token
    $response.auth.client_token
    '''
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_login],
            capture_output=True,
            text=True,
            check=True
        )
        token = result.stdout.strip()
        if not token:
            print("Failed to obtain Vault token. See stderr for details:", result.stderr, file=sys.stderr)
            sys.exit(1)
        os.environ["VAULT_TOKEN"] = token
        print("✅ Successfully logged in to Vault.")
    except subprocess.CalledProcessError as e:
        print("❌ Vault login error:", e.stderr, file=sys.stderr)
        sys.exit(1)

def list_keys(path):
    """
    List KV secrets at the given path.
    Returns a list of keys or None if the path is a leaf secret.
    """
    # Ensure trailing slash for list operation
    target = f"{MOUNT}/{path}".rstrip("/") + "/"
    try:
        output = subprocess.check_output(
            ["vault", "kv", "list", "-format=json", target],
            env=os.environ
        )
        return json.loads(output) or []
    except subprocess.CalledProcessError:
        return None

def get_value(path):
    """
    Get the KV secret data at the given path.
    Returns the parsed JSON object.
    """
    target = f"{MOUNT}/{path}".rstrip("/")
    output = subprocess.check_output(
        ["vault", "kv", "get", "-format=json", target],
        env=os.environ
    )
    return json.loads(output)

def explore():
    """
    Interactive navigation through Vault KV secrets.
    """
    path = ""
    while True:
        keys = list_keys(path)
        if keys is None:
            # Leaf secret: display its JSON and allow going back
            data = get_value(path)
            print(json.dumps(data, indent=2, ensure_ascii=False))
            input("Press [Enter] to go back...")
            path = "/".join(path.split("/")[:-1])
            continue

        print(f"\n🔍 Current path: /{path}")
        for idx, key in enumerate(keys):
            print(f"  {idx}: {key}")
        command = input("Enter index to navigate, 'b' to go back, 'q' to quit: ").strip().lower()

        if command == "q":
            break
        elif command == "b":
            path = "/".join(path.split("/")[:-1])
        elif command.isdigit() and 0 <= int(command) < len(keys):
            selected = keys[int(command)]
            path = f"{path}/{selected}".strip("/")
        else:
            print("Invalid option, please try again.")

def main():
    initialize()
    explore()

if __name__ == "__main__":
    main()
