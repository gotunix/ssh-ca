# ----------------------------------------------------------------------------------------------- #
#                 $$$$$$\   $$$$$$\ $$$$$$$$\ $$\   $$\ $$\   $$\ $$$$$$\ $$\   $$\               #
#                $$  __$$\ $$  __$$\\__$$  __|$$ |  $$ |$$$\  $$ |\_$$  _|$$ |  $$ |              #
#                $$ /  \__|$$ /  $$ |  $$ |   $$ |  $$ |$$$$\ $$ |  $$ |  \$$\ $$  |              #
#                $$ |$$$$\ $$ |  $$ |  $$ |   $$ |  $$ |$$ $$\$$ |  $$ |   \$$$$  /               #
#                $$ |\_$$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ \$$$$ |  $$ |   $$  $$<                #
#                $$ |  $$ |$$ |  $$ |  $$ |   $$ |  $$ |$$ |\$$$ |  $$ |  $$  /\$$\               #
#                \$$$$$$  | $$$$$$  |  $$ |   \$$$$$$  |$$ | \$$ |$$$$$$\ $$ /  $$ |              #
#                 \______/  \______/   \__|    \______/ \__|  \__|\______|\__|  \__|              #
# ----------------------------------------------------------------------------------------------- #
# Copyright (C) GOTUNIX Networks                                                                  #
# Copyright (C) Justin Ovens                                                                      #
# LICENSE: SPDX - AGPL-3.0-or-later                                                               #
# ----------------------------------------------------------------------------------------------- #
# This program is free software: you can redistribute it and/or modify                            #
# it under the terms of the GNU Affero General Public License as                                  #
# published by the Free Software Foundation, either version 3 of the                              #
# License, or (at your option) any later version.                                                 #
#                                                                                                 #
# This program is distributed in the hope that it will be useful,                                 #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                                  #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                   #
# GNU Affero General Public License for more details.                                             #
#                                                                                                 #
# You should have received a copy of the GNU Affero General Public License                        #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                          #
# ----------------------------------------------------------------------------------------------- #
"""
SSH Certificate Authority (CA) Management Tool

This script provides a complete SSH CA solution for:
- Generating SSH CA key pairs
- Signing user public keys with certificates
- Tracking all signed certificates
- Managing Key Revocation Lists (KRL)
- Revoking certificates
- Distributing KRL to remote servers

Directory Structure:
    ~/.sshca/
    ├── <ca-name>/              # CA directory (e.g., ~/.sshca/prod-ca/)
    │   ├── ca                  # CA private key
    │   ├── ca.pub              # CA public key
    │   ├── certificates.json   # Certificate database
    │   └── revoked_keys.krl    # Key Revocation List
    ├── inventory/              # Inventory files (optional)
    └── reports/                # Custom report templates (optional)

Usage:
    # Initialize a new CA (creates ~/.sshca/MyCompany-CA/)
    python sshca.py init --name "MyCompany-CA"

    # Initialize an encrypted CA (recommended for production)
    python sshca.py init --name "Production-CA" --prompt-passphrase

    # Sign a user's public key (1 year validity)
    python sshca.py sign --public-key user.pub --identity user@example.com \
        --principals user,admin --validity 1y

    # Sign with custom duration (1 day, 1 week, 6 months, etc.)
    python sshca.py sign --public-key user.pub --identity user@example.com \
                         --principals user --validity 1d
    python sshca.py sign --public-key user.pub --identity user@example.com \
                         --principals user --validity 1w
    python sshca.py sign --public-key user.pub --identity user@example.com \
                         --principals user --validity 6M

    # Sign same key with multiple CAs (use --output to avoid overwriting)
    python sshca.py --ca-dir ~/.sshca/prod-ca sign user.pub --identity user@prod \
                    --principals user --output user-cert-prod.pub
    python sshca.py --ca-dir ~/.sshca/staging-ca sign user.pub --identity user@staging \
                    --principals user --output user-cert-staging.pub
    python sshca.py --ca-dir ~/.sshca/dev-ca sign user.pub --identity user@dev \
                    --principals user,admin --output user-cert-dev.pub

    # Sign a key on a remote server
    python sshca.py sign-remote --server web1.example.com \
                                --remote-key /home/alice/.ssh/id_ed25519.pub
                                --identity alice@example.com --principals alice,webadmin \
                                --validity 1y

    # List all signed certificates
    python sshca.py list

    # Revoke a certificate
    python sshca.py revoke --serial 1 --reason "User left company"

    # Update the KRL
    python sshca.py update-krl

    # Push KRL to remote servers
    python sshca.py push-krl --inventory ssh-inventory.yaml

    # Push KRL to specific group or servers
    python sshca.py push-krl --inventory ssh-inventory.yaml --limit webservers
    python sshca.py push-krl --inventory ssh-inventory.yaml --limit "prod*"

    # Push CA public key to remote servers
    python sshca.py push-ca --inventory ssh-inventory.yaml

    # Push CA to specific group or servers
    python sshca.py push-ca --inventory ssh-inventory.yaml --limit webservers
    python sshca.py push-ca --inventory ssh-inventory.yaml --limit "prod*"

    # Remove CA public key from remote servers
    python sshca.py remove-ca --inventory ssh-inventory.yaml

    # Remove CA from specific servers
    python sshca.py remove-ca --inventory ssh-inventory.yaml --limit webservers

    # List CA deployment status on remote servers
    python sshca.py list-ca-deployments --inventory ssh-inventory.yaml

    # Check CA deployment on specific servers
    python sshca.py list-ca-deployments --inventory ssh-inventory.yaml --limit webservers

    # Show CA information
    python sshca.py info

Duration formats:
    1s, 1m, 1h, 1d, 1w, 1M (months), 1y (years)
    Or ssh-keygen format: +52w, -1d:+52w, always

Environment Variables:
    SSHCA_DIR    Default CA directory (default: ~/.sshca)
                 Example: export SSHCA_DIR=/etc/ssh-ca
"""

import argparse
import contextlib
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional


class SSHCA:
    """SSH Certificate Authority manager."""

    def __init__(self, ca_dir: str = "./ssh-ca"):
        """
        Initialize the SSH CA.

        Args:
            ca_dir: Directory to store CA files
        """
        self.ca_dir = Path(ca_dir)
        self.ca_key = self.ca_dir / "ca"
        self.ca_pub = self.ca_dir / "ca.pub"
        self.db_file = self.ca_dir / "certificates.json"
        self.krl_file = self.ca_dir / "revoked_keys.krl"
        self.config_file = self.ca_dir / "ca_config.json"

    def _parse_duration(self, duration: str) -> str:
        """
        Parse duration string and convert to ssh-keygen validity format.

        Supports:
        - ssh-keygen format: +52w, -1d:+52w, always, etc.
        - Simple shortcuts: 1s, 1m, 1h, 1d, 1w, 1M, 1y

        Args:
            duration: Duration string

        Returns:
            ssh-keygen compatible validity string
        """
        # If it already starts with + or -, or is "always", return as-is
        if duration.startswith(("+", "-")) or duration == "always":
            return duration

        # Parse simple duration shortcuts
        import re

        match = re.match(r"^(\d+)([smhdwMy])$", duration)
        if match:
            value = int(match.group(1))
            unit = match.group(2)

            # Convert to ssh-keygen format
            unit_map = {
                "s": "s",  # seconds
                "m": "m",  # minutes
                "h": "h",  # hours
                "d": "d",  # days
                "w": "w",  # weeks
                "M": "w",  # months -> weeks (approximate: 1M = 4w)
                "y": "w",  # years -> weeks (1y = 52w)
            }

            # Convert months and years to weeks
            if unit == "M":
                value = value * 4  # 1 month ≈ 4 weeks
            elif unit == "y":
                value = value * 52  # 1 year = 52 weeks

            return f"+{value}{unit_map[unit]}"

        # If we can't parse it, return as-is and let ssh-keygen validate
        return duration

    def _build_ssh_cmd(
        self, base_cmd: list, ssh_user: str, server: str, password: str = None
    ) -> list:
        """
        Build SSH/SCP command with optional password authentication.

        Args:
            base_cmd: Base command (e.g., ['scp'] or ['ssh'])
            ssh_user: SSH user
            server: Server hostname/IP
            password: Optional password for authentication

        Returns:
            Complete command list
        """
        cmd = base_cmd.copy()

        # Add password authentication if provided
        if password:
            # Use sshpass for password authentication
            cmd = ["sshpass", "-p", password] + cmd

        return cmd

    def _prompt_password(self, server: str, ssh_user: str) -> Optional[str]:
        """
        Prompt for SSH password.

        Args:
            server: Server hostname/IP
            ssh_user: SSH user

        Returns:
            Password string or None
        """
        import getpass

        try:
            password = getpass.getpass(f"Password for {ssh_user}@{server}: ")
            return password if password else None
        except KeyboardInterrupt:
            print("\nPassword prompt cancelled", file=sys.stderr)
            return None

    def _execute_ssh_cmd(
        self,
        base_cmd: list,
        server: str,
        ssh_user: str,
        password: str = None,
        prompt_password: bool = False,
        timeout: int = 30,
        capture_output: bool = True,
    ) -> tuple[bool, str, Optional[str]]:
        """
        Execute an SSH/SCP command with retry logic for password authentication.

        Args:
            base_cmd: The command to run (excluding password wrapper)
            server: Server address
            ssh_user: SSH user
            password: Known password or None
            prompt_password: Whether to prompt for password on failure
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr

        Returns:
            Tuple of (success, output/error_msg, updated_password)
        """
        # Try with current credentials (key or provided password)
        cmd_with_auth = self._build_ssh_cmd(base_cmd, ssh_user, server, password)

        try:
            result = subprocess.run(
                cmd_with_auth,
                capture_output=capture_output,
                text=bool(capture_output),
                check=True,
                timeout=timeout,
            )
            return True, result.stdout if capture_output else "", password

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr or str(e)

            # Check if we should prompt for password
            if prompt_password and not password and "Permission denied" in (error_msg or ""):
                print(f"✗ (key auth failed) - requesting password for {server}")
                new_password = self._prompt_password(server, ssh_user)

                if not new_password:
                    return False, "password prompt cancelled", None

                # Retry with new password
                print(f"Retrying {server} with password...", end=" ", flush=True)
                cmd_with_auth = self._build_ssh_cmd(base_cmd, ssh_user, server, new_password)

                try:
                    result = subprocess.run(
                        cmd_with_auth,
                        capture_output=capture_output,
                        text=bool(capture_output),
                        check=True,
                        timeout=timeout,
                    )
                    return True, result.stdout if capture_output else "", new_password
                except subprocess.CalledProcessError as e2:
                    return False, e2.stderr or str(e2), new_password
                except Exception as e2:
                    return False, str(e2), new_password

            return False, error_msg, password

        except subprocess.TimeoutExpired:
            return False, "timeout", password
        except Exception as e:
            return False, str(e), password

    def _run_remote_cmd(
        self,
        server: str,
        ssh_user: str,
        command: str,
        password: str = None,
        prompt_password: bool = False,
        timeout: int = 10,
    ) -> tuple[bool, str, Optional[str]]:
        """
        Run a command on a remote server via SSH.

        Args:
            server: Server address
            ssh_user: SSH user
            command: Shell command to run
            password: Optional password
            prompt_password: Whether to prompt on failure
            timeout: Timeout in seconds

        Returns:
            Tuple of (success, output, updated_password)
        """
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            f"{ssh_user}@{server}",
            command,
        ]
        return self._execute_ssh_cmd(cmd, server, ssh_user, password, prompt_password, timeout)

    def init_ca(
        self,
        name: str,
        key_type: str = "ed25519",
        comment: str = None,
        passphrase: str = None,
        prompt_passphrase: bool = False,
    ) -> bool:
        """
        Initialize a new SSH CA.

        Args:
            name: Name of the CA
            key_type: Type of key (ed25519, rsa, ecdsa)
            comment: Optional comment for the key
            passphrase: Passphrase to encrypt CA private key (optional)
            prompt_passphrase: Whether to prompt for passphrase

        Returns:
            True if successful
        """
        # Check if CA already exists
        if self.ca_key.exists():
            print(f"Error: CA already exists at {self.ca_dir}", file=sys.stderr)
            print("Use a different directory or remove the existing CA", file=sys.stderr)
            return False

        # Prompt for passphrase if requested
        if prompt_passphrase and not passphrase:
            import getpass

            passphrase = getpass.getpass(
                "Enter passphrase for CA private key (leave empty for no encryption): "
            )
            if passphrase:
                passphrase_confirm = getpass.getpass("Confirm passphrase: ")
                if passphrase != passphrase_confirm:
                    print("Error: Passphrases do not match", file=sys.stderr)
                    return False

        # Create CA directory
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        print("=" * 70)
        print("INITIALIZING SSH CERTIFICATE AUTHORITY")
        print("=" * 70)
        print(f"CA Name: {name}")
        print(f"Key Type: {key_type}")
        print(f"CA Directory: {self.ca_dir.absolute()}")
        print(f"Encryption: {'Yes (passphrase protected)' if passphrase else 'No (unencrypted)'}")
        print()

        # Generate CA key pair
        key_comment = comment or f"{name} SSH CA"
        cmd = [
            "ssh-keygen",
            "-t",
            key_type,
            "-f",
            str(self.ca_key),
            "-C",
            key_comment,
            "-N",
            passphrase or "",  # Empty string for no passphrase
        ]

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✓ CA key pair generated")
            print(f"  Private key: {self.ca_key}")
            print(f"  Public key: {self.ca_pub}")
            if passphrase:
                print("  🔒 Private key is encrypted with passphrase")
        except subprocess.CalledProcessError as e:
            print(f"Error generating CA key: {e.stderr}", file=sys.stderr)
            return False

        # Set restrictive permissions on private key
        os.chmod(self.ca_key, 0o600)

        # Initialize certificate database
        db_data = {
            "ca_name": name,
            "created": datetime.now().isoformat(),
            "key_type": key_type,
            "encrypted": bool(passphrase),
            "next_serial": 1,
            "certificates": [],
            "ca_deployments": [],
        }

        with open(self.db_file, "w") as f:
            json.dump(db_data, f, indent=2)

        print("✓ Certificate database initialized")

        # Create initial (empty) KRL
        self._update_krl([])
        print("✓ Key Revocation List created")

        # Save CA configuration
        config = {
            "name": name,
            "key_type": key_type,
            "encrypted": bool(passphrase),
            "created": datetime.now().isoformat(),
        }

        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)

        print()
        print("=" * 70)
        print("✅ SSH CA INITIALIZED SUCCESSFULLY")
        print("=" * 70)
        print()
        print("Next steps:")
        print(f"  1. Distribute the CA public key ({self.ca_pub}) to your SSH servers")
        print(f"  2. Add to /etc/ssh/sshd_config: TrustedUserCAKeys {self.ca_pub}")
        print("  3. Sign user keys with: python sshca.py sign --public-key <key>")
        if passphrase:
            print("  4. Remember your passphrase - you'll need it for signing operations")
        print()

        return True

    def _load_db(self) -> Dict:
        """Load the certificate database."""
        if not self.db_file.exists():
            print("Error: CA not initialized. Run 'init' first.", file=sys.stderr)
            sys.exit(1)

        with open(self.db_file, "r") as f:
            return json.load(f)

    def _save_db(self, db: Dict):
        """Save the certificate database."""
        with open(self.db_file, "w") as f:
            json.dump(db, f, indent=2)

    def _build_keygen_cmd(
        self,
        identity: str,
        principals: List[str],
        validity: str,
        serial: int,
        cert_type: str,
        options: List[str],
        passphrase: str,
        is_encrypted: bool,
        public_key_file: str,
    ) -> List[str]:
        """Build the ssh-keygen command."""
        cmd = [
            "ssh-keygen",
            "-s",
            str(self.ca_key),
            "-I",
            identity,
            "-n",
            ",".join(principals),
            "-V",
            validity,
            "-z",
            str(serial),
        ]

        # Add passphrase if CA is encrypted
        if is_encrypted and passphrase:
            cmd.extend(["-P", passphrase])

        # Add certificate type
        if cert_type == "host":
            cmd.append("-h")

        # Add options/extensions
        if options:
            for opt in options:
                cmd.extend(["-O", opt])
        else:
            # Default options for user certificates
            if cert_type == "user":
                default_opts = [
                    "clear",
                    "permit-pty",
                    "permit-user-rc",
                    "permit-port-forwarding",
                    "permit-agent-forwarding",
                ]
                for opt in default_opts:
                    cmd.extend(["-O", opt])

        cmd.append(public_key_file)
        return cmd

    def sign_key(
        self,
        public_key_file: str,
        identity: str,
        principals: List[str],
        validity: str = "+52w",
        cert_type: str = "user",
        options: List[str] = None,
        output_file: str = None,
        passphrase: str = None,
    ) -> bool:
        """
        Sign a user's public key with the CA.

        Args:
            public_key_file: Path to user's public key
            identity: Key identity (usually email or username)
            principals: List of principals (usernames) allowed
            validity: Validity period (e.g., "+52w" for 52 weeks)
            cert_type: Certificate type ("user" or "host")
            options: List of certificate options/extensions
            output_file: Output file for certificate (default: <key>-cert.pub)
            passphrase: CA passphrase (if encrypted)

        Returns:
            True if successful
        """
        if not Path(public_key_file).exists():
            print(f"Error: Public key file not found: {public_key_file}", file=sys.stderr)
            return False

        if not self.ca_key.exists():
            print("Error: CA not initialized. Run 'init' first.", file=sys.stderr)
            return False

        # Check if CA is encrypted and prompt for passphrase if needed
        db = self._load_db()
        is_encrypted = db.get("encrypted", False)

        if is_encrypted and not passphrase:
            import getpass

            passphrase = getpass.getpass("Enter CA passphrase: ")
            if not passphrase:
                print("Error: Passphrase required for encrypted CA", file=sys.stderr)
                return False

        serial = db["next_serial"]

        # Parse and validate duration
        parsed_validity = self._parse_duration(validity)

        # Determine output file
        if output_file is None:
            pub_key_path = Path(public_key_file)
            output_file = str(pub_key_path.parent / f"{pub_key_path.stem}-cert.pub")

        print("=" * 70)
        print("SIGNING SSH PUBLIC KEY")
        print("=" * 70)
        print(f"Public Key: {public_key_file}")
        print(f"Identity: {identity}")
        print(f"Principals: {', '.join(principals)}")
        print(f"Serial: {serial}")
        print(f"Validity: {validity} (parsed as: {parsed_validity})")
        print(f"Type: {cert_type}")
        if is_encrypted:
            print("CA: 🔒 Encrypted")
        print()

        # Build ssh-keygen command
        cmd = self._build_keygen_cmd(
            identity,
            principals,
            parsed_validity,
            serial,
            cert_type,
            options,
            passphrase,
            is_encrypted,
            public_key_file,
        )

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("✓ Certificate signed successfully")
            print(f"  Certificate: {output_file}")
        except subprocess.CalledProcessError as e:
            if "incorrect passphrase" in e.stderr.lower() or "bad passphrase" in e.stderr.lower():
                print("✗ Error: Incorrect passphrase", file=sys.stderr)
            else:
                print(f"Error signing key: {e.stderr}", file=sys.stderr)
            return False

        # Record certificate in database
        cert_record = {
            "serial": serial,
            "identity": identity,
            "principals": principals,
            "public_key_file": public_key_file,
            "cert_file": output_file,
            "cert_type": cert_type,
            "validity": validity,
            "signed_at": datetime.now().isoformat(),
            "revoked": False,
            "revoked_at": None,
            "options": options or [],
        }

        db["certificates"].append(cert_record)
        db["next_serial"] = serial + 1
        self._save_db(db)

        print("✓ Certificate recorded in database")

        # Show certificate info
        print()
        print("Certificate Information:")
        self._show_cert_info(output_file)

        print()
        print("=" * 70)
        print("✅ KEY SIGNED SUCCESSFULLY")
        print("=" * 70)
        print()
        print("Next steps:")
        print(f"  1. Send {output_file} to the user")
        print("  2. User should place it alongside their private key")
        print("  3. SSH will automatically use the certificate")
        print()

        return True

    def sign_remote_key(
        self,
        server: str,
        remote_key_path: str,
        identity: str,
        principals: List[str],
        validity: str = "+52w",
        cert_type: str = "user",
        options: List[str] = None,
        ssh_user: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        Sign a public key that lives on a remote server.

        Fetches the key, signs it locally, and pushes the certificate back.

        Args:
            server: Remote server (hostname or IP)
            remote_key_path: Path to public key on remote server
            identity: Key identity (usually email or username)
            principals: List of principals (usernames) allowed
            validity: Validity period (e.g., "1y", "+52w")
            cert_type: Certificate type ("user" or "host")
            options: List of certificate options/extensions
            ssh_user: SSH user for connecting (default: current user)
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if successful
        """
        import tempfile

        if not self.ca_key.exists():
            print("Error: CA not initialized. Run 'init' first.", file=sys.stderr)
            return False

        # Determine SSH user
        if not ssh_user:
            ssh_user = os.environ.get("USER")

        print("=" * 70)
        print("SIGNING REMOTE SSH PUBLIC KEY")
        print("=" * 70)
        print(f"Server: {server}")
        print(f"SSH User: {ssh_user}")
        print(f"Remote Key: {remote_key_path}")
        print(f"Identity: {identity}")
        print(f"Principals: {', '.join(principals)}")
        print(f"Validity: {validity}")
        print(f"Auth: {'Password' if password or prompt_password else 'SSH Key'}")
        print()

        # Create temporary directory for working files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            local_key = temp_dir_path / "remote_key.pub"
            local_cert = temp_dir_path / "remote_key-cert.pub"

            # Step 1: Fetch the public key from remote server
            print("Step 1: Fetching public key from remote server...", end=" ", flush=True)

            scp_fetch_cmd = [
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{ssh_user}@{server}:{remote_key_path}",
                str(local_key),
            ]

            success, output, password = self._execute_ssh_cmd(
                scp_fetch_cmd, server, ssh_user, password, prompt_password
            )

            if not success:
                print(f"✗\nError fetching key: {output}", file=sys.stderr)
                return False
            print("✓")

            # Step 2: Sign the key locally
            print("Step 2: Signing key locally...", end=" ", flush=True)

            # Delegate to sign_key
            print("(delegating to sign_key)")
            print()

            sign_success = self.sign_key(
                str(local_key),
                identity,
                principals,
                validity,
                cert_type,
                options,
                output_file=str(local_cert),
            )

            if not sign_success:
                print("✗\nError: Failed to sign key", file=sys.stderr)
                return False

            # Step 3: Push the certificate back to remote server
            # Determine remote certificate path (same location as key, with -cert.pub suffix)
            if remote_key_path.endswith(".pub"):
                remote_cert_path = remote_key_path.replace(".pub", "-cert.pub")
            else:
                remote_cert_path = f"{remote_key_path}-cert.pub"

            print(
                f"Step 3: Pushing certificate to remote server ({remote_cert_path})...",
                end=" ",
                flush=True,
            )
            scp_push_cmd = [
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                str(local_cert),
                f"{ssh_user}@{server}:{remote_cert_path}",
            ]

            success, output, password = self._execute_ssh_cmd(
                scp_push_cmd, server, ssh_user, password, prompt_password
            )

            if not success:
                print(f"✗\nError pushing certificate: {output}", file=sys.stderr)
                return False
            print("✓")

        print()
        print("=" * 70)
        print("✅ REMOTE KEY SIGNED SUCCESSFULLY")
        print("=" * 70)
        print()
        print("Certificate Details:")
        print(f"  Remote Server: {server}")
        print(f"  Certificate Path: {remote_cert_path}")
        print(f"  Identity: {identity}")
        print(f"  Principals: {', '.join(principals)}")
        print(f"  Validity: {validity}")
        print()
        print("The certificate is now available on the remote server.")
        print("SSH will automatically use it when connecting.")
        print()

        return True

    def _show_cert_info(self, cert_file: str):
        """Display certificate information."""
        try:
            result = subprocess.run(
                ["ssh-keygen", "-L", "-f", cert_file], capture_output=True, text=True, check=True
            )
            print(result.stdout)
        except subprocess.CalledProcessError:
            pass

    def list_certificates(self, show_revoked: bool = True):
        """List all signed certificates."""
        db = self._load_db()

        print("=" * 70)
        print(f"SSH CA: {db['ca_name']}")
        print("=" * 70)
        print(f"Created: {db['created']}")
        print(f"Total Certificates: {len(db['certificates'])}")
        print()

        if not db["certificates"]:
            print("No certificates signed yet.")
            return

        # Filter certificates
        certs = db["certificates"]
        if not show_revoked:
            certs = [c for c in certs if not c["revoked"]]

        # Count statuses
        active_count = 0
        revoked_count = 0
        expired_count = 0

        for cert in db["certificates"]:
            if cert["revoked"]:
                revoked_count += 1
            elif self._is_certificate_expired(cert):
                expired_count += 1
            else:
                active_count += 1

        print(f"Active: {active_count} | Expired: {expired_count} | Revoked: {revoked_count}")
        print()

        print(f"{'Serial':<8} {'Identity':<30} {'Principals':<20} {'Validity':<20} {'Status':<12}")
        print("-" * 95)

        for cert in certs:
            # Determine status
            if cert["revoked"]:
                status = "REVOKED"
            elif self._is_certificate_expired(cert):
                status = "EXPIRED"
            else:
                status = "ACTIVE"

            principals = ",".join(cert["principals"][:2])
            if len(cert["principals"]) > 2:
                principals += "..."

            # Parse validity to show expiration
            validity_display = cert.get("validity", "N/A")

            print(
                f"{cert['serial']:<8} {cert['identity']:<30} {principals:<20} "
                f"{validity_display:<20} {status:<12}"
            )

    def _is_certificate_expired(self, cert: dict) -> bool:
        """
        Check if a certificate is expired based on its validity period.

        Args:
            cert: Certificate record from database

        Returns:
            True if expired
        """
        try:
            validity = cert.get("validity", "")
            signed_at = datetime.fromisoformat(cert["signed_at"])
            expiration = self._get_expiration_date(signed_at, validity)

            if not expiration:
                return False

            return datetime.now() > expiration
        except Exception:
            return False

    def _get_expiration_date(self, signed_at: datetime, validity: str) -> Optional[datetime]:
        """Calculate expiration date from validity string."""
        import re

        # Handle formats like "+52w", "+1d", "1m", "1y", etc.
        match = re.match(r"^\+?(\d+)([smhdwMy])$", validity)

        if not match:
            return None

        value = int(match.group(1))
        unit = match.group(2)

        # Convert months and years to weeks/days
        if unit == "M":
            value = value * 4  # 1 month ≈ 4 weeks
            unit = "w"
        elif unit == "y":
            value = value * 52  # 1 year = 52 weeks
            unit = "w"

        time_deltas = {
            "s": timedelta(seconds=value),
            "m": timedelta(minutes=value),
            "h": timedelta(hours=value),
            "d": timedelta(days=value),
            "w": timedelta(weeks=value),
        }

        if unit not in time_deltas:
            return None

        return signed_at + time_deltas[unit]

    def revoke_certificate(self, serial: int, reason: str = None) -> bool:
        """
        Revoke a certificate by serial number.

        Args:
            serial: Serial number of certificate to revoke
            reason: Optional reason for revocation

        Returns:
            True if successful
        """
        db = self._load_db()

        # Find certificate
        cert = None
        for c in db["certificates"]:
            if c["serial"] == serial:
                cert = c
                break

        if not cert:
            print(f"Error: Certificate with serial {serial} not found", file=sys.stderr)
            return False

        if cert["revoked"]:
            print(f"Certificate {serial} is already revoked", file=sys.stderr)
            return False

        print("=" * 70)
        print("REVOKING CERTIFICATE")
        print("=" * 70)
        print(f"Serial: {serial}")
        print(f"Identity: {cert['identity']}")
        print(f"Principals: {', '.join(cert['principals'])}")
        if reason:
            print(f"Reason: {reason}")
        print()

        # Mark as revoked
        cert["revoked"] = True
        cert["revoked_at"] = datetime.now().isoformat()
        if reason:
            cert["revocation_reason"] = reason

        self._save_db(db)
        print("✓ Certificate marked as revoked in database")

        # Update KRL
        revoked_serials = [c["serial"] for c in db["certificates"] if c["revoked"]]
        self._update_krl(revoked_serials)

        print()
        print("=" * 70)
        print("✅ CERTIFICATE REVOKED")
        print("=" * 70)
        print()
        print("Next steps:")
        print(f"  1. Distribute updated KRL ({self.krl_file}) to SSH servers")
        print(f"  2. Add to /etc/ssh/sshd_config: RevokedKeys {self.krl_file}")
        print()

        return True

    def _update_krl(self, serials: List[int]) -> bool:
        """
        Update the Key Revocation List.

        Args:
            serials: List of serial numbers to revoke

        Returns:
            True if successful
        """
        import tempfile

        if not serials:
            # Create empty KRL
            cmd = ["ssh-keygen", "-k", "-f", str(self.krl_file), str(self.ca_pub)]
        else:
            # Create KRL specification file for multiple serials
            # ssh-keygen doesn't accept comma-separated serials in -z
            # Instead, we need to use a KRL spec file with serial: directives
            try:
                # Create temporary KRL spec file
                with tempfile.NamedTemporaryFile(mode="w", suffix=".krl", delete=False) as f:
                    krl_spec_file = f.name
                    # Write serial directives
                    for serial in serials:
                        f.write(f"serial: {serial}\n")

                # Generate KRL from spec file
                cmd = [
                    "ssh-keygen",
                    "-k",
                    "-f",
                    str(self.krl_file),
                    "-s",
                    str(self.ca_pub),
                    krl_spec_file,
                ]

                try:
                    subprocess.run(cmd, capture_output=True, text=True, check=True)
                    print(f"✓ KRL updated: {self.krl_file}")
                    return True
                except subprocess.CalledProcessError as e:
                    print(f"Error updating KRL: {e.stderr}", file=sys.stderr)
                    return False
                finally:
                    # Clean up temp file
                    import os

                    with contextlib.suppress(OSError):
                        os.unlink(krl_spec_file)

            except Exception as e:
                print(f"Error creating KRL spec file: {e}", file=sys.stderr)
                return False

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"✓ KRL updated: {self.krl_file}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error updating KRL: {e.stderr}", file=sys.stderr)
            return False

    def update_krl(self) -> bool:
        """Manually update the KRL from the database."""
        db = self._load_db()
        revoked_serials = [c["serial"] for c in db["certificates"] if c["revoked"]]

        print("=" * 70)
        print("UPDATING KEY REVOCATION LIST")
        print("=" * 70)
        print(f"Revoked certificates: {len(revoked_serials)}")
        if revoked_serials:
            print(f"Serials: {', '.join(str(s) for s in revoked_serials)}")
        print()

        return self._update_krl(revoked_serials)

    def _resolve_inventory_path(self, inventory_file: str) -> Path:
        """
        Resolve inventory file path.

        Checks ~/.sshca/inventory/ for relative paths.

        Args:
            inventory_file: Inventory file path (absolute or relative)

        Returns:
            Resolved Path object
        """
        inventory_path = Path(inventory_file)

        if not inventory_path.is_absolute() and not inventory_path.exists():
            # Try ~/.sshca/inventory/ directory
            default_inventory_dir = Path.home() / ".sshca" / "inventory"
            alternative_path = default_inventory_dir / inventory_file
            if alternative_path.exists():
                return alternative_path

        return inventory_path

    def _load_inventory_file(self, inventory_file: str) -> Optional[dict]:
        """Load inventory file safely."""
        # Resolve inventory path - check ~/.sshca/inventory/ for relative paths
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return None

        try:
            import yaml

            with open(inventory_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading inventory file: {e}", file=sys.stderr)
            return None

    def _extract_raw_servers(self, inventory: dict) -> tuple[list, dict]:
        """Extract raw server list and host map from inventory."""
        servers = []
        host_map = {}

        # Check for simple servers list (backward compatibility)
        if "servers" in inventory and isinstance(inventory["servers"], list):
            servers = inventory["servers"]
            host_map = {s: s for s in servers}

        # Check for Ansible-style groups
        elif "all" in inventory:
            host_map = self._parse_ansible_inventory(inventory)
            servers = list(host_map.keys())

        # Check for custom groups format
        elif "groups" in inventory:
            groups = inventory.get("groups", {})
            for _, group_servers in groups.items():
                if isinstance(group_servers, list):
                    servers.extend(group_servers)
            servers = list(dict.fromkeys(servers))  # Deduplicate

        return servers, host_map

    def _filter_servers(self, servers: list, inventory: dict, limit: str) -> list:
        """Filter servers based on limit pattern."""
        if not limit:
            return servers

        limit_patterns = [p.strip() for p in limit.split(",")]
        filtered_servers = []
        groups = inventory.get("groups", {})

        for pattern in limit_patterns:
            # Check if it's a group name
            if pattern in groups:
                group_servers = groups[pattern]
                if isinstance(group_servers, list):
                    filtered_servers.extend(group_servers)
                    print(f"Using group '{pattern}': {len(group_servers)} server(s)")
            else:
                # Support wildcards and exact matches
                import fnmatch

                matched = [s for s in servers if fnmatch.fnmatch(s, pattern) or s == pattern]
                filtered_servers.extend(matched)

        # Deduplicate while preserving order
        return list(dict.fromkeys(filtered_servers))

    def _get_servers_from_inventory(self, inventory: dict, limit: str = None) -> tuple[list, dict]:
        """
        Extract servers from inventory with optional filtering.

        Args:
            inventory: Loaded inventory dict
            limit: Optional limit pattern (comma-separated)

        Returns:
            Tuple of (list of server hostnames, dict mapping hostname -> connection_addr)
        """
        servers, host_map = self._extract_raw_servers(inventory)

        if not servers:
            return [], {}

        # Apply limit if specified
        if limit:
            servers = self._filter_servers(servers, inventory, limit)

            if servers:
                print(f"Limiting to {len(servers)} server(s) matching: {limit}")
                print(
                    f"Matched servers: {', '.join(servers[:10])}"
                    f"{'...' if len(servers) > 10 else ''}"
                )
                print()

        return servers, host_map

    def _extract_direct_hosts(self, group_data: dict) -> Dict[str, str]:
        """Extract direct hosts from a group."""
        hosts = {}
        if "hosts" in group_data:
            if isinstance(group_data["hosts"], dict):
                # Ansible format: hosts: {host1: {ansible_host: ip}, host2: {}}
                for hostname, host_vars in group_data["hosts"].items():
                    if isinstance(host_vars, dict):
                        # Use ansible_host if available, otherwise use hostname
                        connection_addr = host_vars.get("ansible_host", hostname)
                    else:
                        connection_addr = hostname
                    hosts[hostname] = connection_addr
            elif isinstance(group_data["hosts"], list):
                # Simple list format
                for hostname in group_data["hosts"]:
                    hosts[hostname] = hostname
        return hosts

    def _extract_children_hosts(self, group_data: dict) -> Dict[str, str]:
        """Extract hosts from children groups."""
        hosts = {}
        if "children" in group_data and isinstance(group_data["children"], dict):
            for child_group in group_data["children"].values():
                child_hosts = self._extract_hosts_recursive(child_group)
                # Merge, but don't override existing entries
                for hostname, addr in child_hosts.items():
                    if hostname not in hosts:
                        hosts[hostname] = addr
        return hosts

    def _extract_hosts_recursive(self, group_data: dict) -> Dict[str, str]:
        """Recursively extract hosts from Ansible group data."""
        if not isinstance(group_data, dict):
            return {}

        group_host_map = self._extract_direct_hosts(group_data)

        # Get hosts from children groups
        children_hosts = self._extract_children_hosts(group_data)

        # Merge, but don't override existing entries (closest scope wins in Ansible usually,
        # but for simple extraction we just accumulate)
        for hostname, addr in children_hosts.items():
            if hostname not in group_host_map:
                group_host_map[hostname] = addr

        return group_host_map

    def _parse_ansible_inventory(self, inventory: dict) -> Dict[str, str]:
        """
        Parse Ansible-style inventory format and return host mapping.

        Args:
            inventory: Inventory dictionary in Ansible format

        Returns:
            Dict mapping hostname to connection address (uses ansible_host if available)
        """
        host_map = {}

        # Start from 'all' group
        if "all" in inventory:
            host_map = self._extract_hosts_recursive(inventory["all"])

        return host_map

    def _push_krl_to_server(
        self,
        server: str,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        use_sudo: bool,
        password: str,
        prompt_password: bool,
        restart_ssh: bool,
        restart_cmd: str,
    ) -> tuple[bool, str, str]:
        """Push KRL to a single server."""
        print(f"Pushing to {server}...", end=" ", flush=True)

        # Get connection address
        connection_addr = host_map.get(server, server)

        # Create a temporary location for the file
        temp_path = f"/tmp/revoked_keys.krl.{os.getpid()}"

        # Step 1: SCP to temp location
        scp_cmd = [
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            str(self.krl_file),
            f"{ssh_user}@{connection_addr}:{temp_path}",
        ]

        success, output, password = self._execute_ssh_cmd(
            scp_cmd, server, ssh_user, password, prompt_password
        )

        if not success:
            print(f"✗ ({output.strip()})")
            return False, output.strip(), password

        # Step 2: Move to final location
        move_cmd_str = f"mv {temp_path} {dest_path} && chmod 644 {dest_path}"
        if use_sudo:
            move_cmd_str = f"sudo {move_cmd_str} && sudo chown root:root {dest_path}"

        success, output, password = self._run_remote_cmd(
            connection_addr, ssh_user, move_cmd_str, password, False
        )

        if not success:
            print(f"✗ (move failed: {output.strip()})")
            # Try cleanup
            self._run_remote_cmd(connection_addr, ssh_user, f"rm -f {temp_path}", password, False)
            return False, f"move failed: {output.strip()}", password

        print("✓")

        # Step 3: Restart SSH if requested
        if restart_ssh:
            if use_sudo:
                restart_cmd = f"sudo {restart_cmd}"

            success, output, password = self._run_remote_cmd(
                connection_addr, ssh_user, restart_cmd, password, False
            )
            if success:
                print(f"  ✓ SSH service reloaded on {server}")
            else:
                print(f"  ⚠️  Warning: Could not reload SSH on {server}: {output.strip()}")

        return True, "", password

    def _update_db_deployment(self, deployed_servers: list):
        """Update database with KRL deployment tracking."""
        if not deployed_servers:
            return

        # Calculate KRL checksum
        try:
            with open(self.krl_file, "rb") as f:
                krl_checksum = hashlib.md5(f.read()).hexdigest()
        except Exception:
            krl_checksum = "unknown"

        db = self._load_db()

        # Ensure krl_deployments exists
        if "krl_deployments" not in db:
            db["krl_deployments"] = []

        # Find or create deployment record for this checksum
        deployment = None
        for d in db["krl_deployments"]:
            if d.get("checksum") == krl_checksum:
                deployment = d
                break

        if not deployment:
            deployment = {
                "checksum": krl_checksum,
                "servers": [],
                "first_deployed": datetime.now().isoformat(),
            }
            db["krl_deployments"].append(deployment)

        # Update server list (merge with existing)
        existing_servers = set(deployment.get("servers", []))
        existing_servers.update(deployed_servers)
        deployment["servers"] = sorted(existing_servers)
        deployment["last_updated"] = datetime.now().isoformat()

        self._save_db(db)

    def push_krl(
        self,
        inventory_file: str,
        ssh_user: str = None,
        krl_path: str = "/etc/ssh/revoked_keys.krl",
        limit: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        Push the KRL to remote servers listed in inventory file.

        Args:
            inventory_file: Path to YAML inventory file
            ssh_user: SSH user (default: current user)
            krl_path: Destination path on remote servers
            limit: Limit to specific hosts/groups
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if all pushes succeeded
        """
        if not Path(inventory_file).exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return False

        if not self.krl_file.exists():
            print(f"Error: KRL file not found: {self.krl_file}", file=sys.stderr)
            print("Run 'update-krl' first to create the KRL", file=sys.stderr)
            return False

        # Load inventory
        inventory = self._load_inventory_file(inventory_file)
        if not inventory:
            return False

        # Get servers
        servers, host_map = self._get_servers_from_inventory(inventory, limit)
        if not servers:
            return False

        # Get SSH user (prefer service account over root)
        if not ssh_user:
            ssh_user = inventory.get("ssh_user", os.environ.get("USER"))

        # Get destination path
        dest_path = inventory.get("krl_path", krl_path)

        # Check if we should use sudo
        use_sudo = inventory.get("use_sudo", True)

        print("=" * 70)
        print("PUSHING KRL TO REMOTE SERVERS")
        print("=" * 70)
        print(f"KRL File: {self.krl_file}")
        print(f"Destination: {dest_path}")
        print(f"SSH User: {ssh_user}")
        print(f"Use sudo: {use_sudo}")
        print(f"Servers: {len(servers)}")
        print()

        success_count = 0
        failed_servers = []
        deployed_servers = []

        restart_ssh = inventory.get("restart_ssh", False)
        restart_cmd = inventory.get("restart_command", "systemctl reload sshd")

        # Track if we've prompted for password
        server_password = password

        for server in servers:
            success, output, server_password = self._push_krl_to_server(
                server,
                host_map,
                ssh_user,
                dest_path,
                use_sudo,
                server_password,
                prompt_password,
                restart_ssh,
                restart_cmd,
            )

            if success:
                success_count += 1
                deployed_servers.append(server)
            else:
                failed_servers.append((server, output))

        print()

        # Update database with deployment tracking
        self._update_db_deployment(deployed_servers)

        print()
        print("=" * 70)
        print(f"✅ Successfully pushed to {success_count}/{len(servers)} servers")

        if failed_servers:
            print("❌ Failed servers:")
            for server, error in failed_servers:
                print(f"  - {server}: {error}")

        print("=" * 70)
        return success_count == len(servers)

    def _get_ca_fingerprint(self) -> Optional[str]:
        """
        Get the fingerprint of the CA public key.

        Returns:
            CA fingerprint (e.g., SHA256:...) or None if error
        """
        try:
            result = subprocess.run(
                ["ssh-keygen", "-l", "-f", str(self.ca_pub)],
                capture_output=True,
                text=True,
                check=True,
            )
            # Output format: "256 SHA256:... comment (ED25519)"
            # Extract the fingerprint part
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]  # SHA256:...
            return None
        except subprocess.CalledProcessError:
            return None

    def _build_append_ca_cmd(
        self, dest_path: str, temp_path: str, ca_content_escaped: str, use_sudo: bool
    ) -> str:
        """Build the command to check for CA key existence and append if missing."""
        if use_sudo:
            return (
                f"sudo touch {dest_path} && "
                f"if ! sudo grep -qF '{ca_content_escaped}' {dest_path} 2>/dev/null; then "
                f"  sudo tee -a {dest_path} < {temp_path} >/dev/null && "
                f"  sudo chmod 644 {dest_path} && "
                f"  sudo chown root:root {dest_path} && "
                f"  echo 'added'; "
                f"else "
                f"  echo 'exists'; "
                f"fi && "
                f"rm -f {temp_path}"
            )
        else:
            return (
                f"touch {dest_path} && "
                f"if ! grep -qF '{ca_content_escaped}' {dest_path} 2>/dev/null; then "
                f"  cat {temp_path} >> {dest_path} && "
                f"  chmod 644 {dest_path} && "
                f"  echo 'added'; "
                f"else "
                f"  echo 'exists'; "
                f"fi && "
                f"rm -f {temp_path}"
            )

    def _restart_ssh_service(
        self,
        server: str,
        connection_addr: str,
        ssh_user: str,
        password: str,
        restart_cmd: str,
        use_sudo: bool,
    ) -> tuple[bool, str, str]:
        """Restart SSH service on remote server."""
        if use_sudo and not restart_cmd.strip().startswith("sudo"):
            # Fix: apply sudo to the restart command properly
            restart_cmd = f"sudo {restart_cmd}"

        success, output, password = self._run_remote_cmd(
            connection_addr, ssh_user, restart_cmd, password, False
        )

        if success:
            print(f"  ✓ SSH service reloaded on {server}")
        else:
            print(f"  ⚠️  Warning: Could not reload SSH on {server}: {output.strip()}")

        return success, output, password

    def _push_ca_to_server(
        self,
        server: str,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        use_sudo: bool,
        password: str,
        prompt_password: bool,
        restart_ssh: bool,
        restart_cmd: str,
    ) -> tuple[bool, str, str]:
        """Push CA public key to a single server."""
        print(f"Pushing to {server}...", end=" ", flush=True)

        connection_addr = host_map.get(server, server)
        temp_path = f"/tmp/ca_pub.{os.getpid()}"

        try:
            # SCP to temp location
            scp_cmd = [
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                str(self.ca_pub),
                f"{ssh_user}@{connection_addr}:{temp_path}",
            ]

            success, output, password = self._execute_ssh_cmd(
                scp_cmd, server, ssh_user, password, prompt_password
            )

            if not success:
                print(f"✗ ({output.strip()})")
                return False, output.strip(), password

            # Check if CA already exists and append if not
            with open(self.ca_pub, "r") as f:
                ca_content = f.read().strip()
            ca_content_escaped = ca_content.replace("'", "'\\''")

            cmd_str = self._build_append_ca_cmd(dest_path, temp_path, ca_content_escaped, use_sudo)

            success, output, password = self._run_remote_cmd(
                connection_addr, ssh_user, cmd_str, password, False
            )

            if success:
                if "added" in output:
                    print("✓ (added)")
                elif "exists" in output:
                    print("✓ (already present)")
                else:
                    print("✓")

                if restart_ssh:
                    self._restart_ssh_service(
                        server,
                        connection_addr,
                        ssh_user,
                        password,
                        restart_cmd,
                        use_sudo,
                    )
                return True, "", password
            else:
                print(f"✗ ({output.strip()})")
                self._run_remote_cmd(
                    connection_addr, ssh_user, f"rm -f {temp_path}", password, False
                )
                return False, output.strip(), password

        except Exception as e:
            print(f"✗ ({str(e)})")
            with contextlib.suppress(Exception):
                self._run_remote_cmd(
                    connection_addr, ssh_user, f"rm -f {temp_path}", password, False
                )
            return False, str(e), password

    def _update_db_ca_deployment(self, deployed_servers: list, ca_fingerprint: str):
        """Update database with CA deployment tracking."""
        if not deployed_servers:
            return

        db = self._load_db()

        if "ca_deployments" not in db:
            db["ca_deployments"] = []

        deployment = None
        for d in db["ca_deployments"]:
            if d.get("fingerprint") == ca_fingerprint:
                deployment = d
                break

        if not deployment:
            deployment = {
                "fingerprint": ca_fingerprint,
                "servers": [],
                "first_deployed": datetime.now().isoformat(),
            }
            db["ca_deployments"].append(deployment)

        existing_servers = set(deployment.get("servers", []))
        existing_servers.update(deployed_servers)
        deployment["servers"] = sorted(existing_servers)
        deployment["last_updated"] = datetime.now().isoformat()

        self._save_db(db)

    def _validate_and_load_push_ca(
        self, inventory_file: str, limit: str
    ) -> Optional[tuple[dict, list, dict, str, str]]:
        """Validate files and load inventory/CA content."""
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return None

        if not self.ca_pub.exists():
            print(f"Error: CA public key not found: {self.ca_pub}", file=sys.stderr)
            print("Run 'init' first to create the CA", file=sys.stderr)
            return None

        # Get CA fingerprint for tracking and idempotency
        ca_fingerprint = self._get_ca_fingerprint()
        if not ca_fingerprint:
            print("Error: Could not get CA fingerprint", file=sys.stderr)
            return None

        # Load inventory
        inventory = self._load_inventory_file(inventory_file)
        if not inventory:
            return None

        # Get servers
        servers, host_map = self._get_servers_from_inventory(inventory, limit)
        if not servers:
            return None

        # Read the CA public key content
        try:
            with open(self.ca_pub, "r") as f:
                ca_content = f.read().strip()
        except Exception as e:
            print(f"Error reading CA public key: {e}", file=sys.stderr)
            return None

        # Escape single quotes in the key content for the shell command
        ca_content_escaped = ca_content.replace("'", "'\\''")

        return inventory, servers, host_map, ca_fingerprint, ca_content_escaped

    def push_ca(
        self,
        inventory_file: str,
        ssh_user: str = None,
        ca_path: str = "/etc/ssh/ca.pub",
        limit: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        Push the CA public key to remote servers listed in inventory file.

        Args:
            inventory_file: Path to YAML inventory file
            ssh_user: SSH user (default: current user)
            ca_path: Destination path on remote servers
            limit: Limit to specific hosts/groups
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if all pushes succeeded
        """
        result = self._validate_and_load_push_ca(inventory_file, limit)
        if not result:
            return False
        inventory, servers, host_map, ca_fingerprint, ca_content_escaped = result

        # Get SSH user (prefer service account over root)
        if not ssh_user:
            ssh_user = inventory.get("ssh_user", os.environ.get("USER"))

        # Get destination path
        dest_path = inventory.get("ca_path", ca_path)

        # Check if we should use sudo
        use_sudo = inventory.get("use_sudo", True)

        print("=" * 70)
        print("PUSHING CA PUBLIC KEY TO REMOTE SERVERS")
        print("=" * 70)
        print(f"CA Public Key: {self.ca_pub}")
        print(f"CA Fingerprint: {ca_fingerprint}")
        print(f"Destination: {dest_path}")
        print(f"SSH User: {ssh_user}")
        print(f"Use sudo: {use_sudo}")
        print(f"Servers: {len(servers)}")
        print()

        success_count = 0
        failed_servers = []
        deployed_servers = []

        # Get restart settings
        restart_ssh = inventory.get("restart_ssh", False)
        restart_cmd = inventory.get("restart_command", "systemctl reload sshd")

        # Track if we've prompted for password
        server_password = password

        for server in servers:
            success, output, server_password = self._push_ca_to_server(
                server,
                host_map,
                ssh_user,
                dest_path,
                use_sudo,
                server_password,
                prompt_password,
                restart_ssh,
                restart_cmd,
            )

            if success:
                success_count += 1
                deployed_servers.append(server)
            else:
                failed_servers.append((server, output))

        # Update database with deployment tracking
        self._update_db_ca_deployment(deployed_servers, ca_fingerprint)

        print()
        print("=" * 70)
        print(f"✅ Successfully pushed to {success_count}/{len(servers)} servers")

        if failed_servers:
            print("❌ Failed servers:")
            for server, error in failed_servers:
                print(f"  - {server}: {error}")

        print("=" * 70)
        print()
        print("Next steps:")
        print(f"  1. Verify CA is in {dest_path} on remote servers")
        print(f"  2. Configure sshd_config: TrustedUserCAKeys {dest_path}")
        print("  3. Reload SSH service if not done automatically")
        print()

        return len(failed_servers) == 0

    def _validate_and_load_remove_ca(
        self, inventory_file: str, limit: str
    ) -> Optional[tuple[dict, list, dict, str, str]]:
        """Validate files and load inventory/CA content for remove_ca."""
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return None

        if not self.ca_pub.exists():
            print(f"Error: CA public key not found: {self.ca_pub}", file=sys.stderr)
            return None

        # Get CA fingerprint for identification
        ca_fingerprint = self._get_ca_fingerprint()
        if not ca_fingerprint:
            print("Error: Could not get CA fingerprint", file=sys.stderr)
            return None

        # Load inventory
        inventory = self._load_inventory_file(inventory_file)
        if not inventory:
            return None

        # Get servers
        servers, host_map = self._get_servers_from_inventory(inventory, limit)
        if not servers:
            return None

        # Read the CA public key content
        try:
            with open(self.ca_pub, "r") as f:
                ca_content = f.read().strip()
        except Exception as e:
            print(f"Error reading CA public key: {e}", file=sys.stderr)
            return None

        # Escape single quotes in the key content for the shell command
        ca_content_escaped = ca_content.replace("'", "'\\''")

        return inventory, servers, host_map, ca_fingerprint, ca_content_escaped

    def _build_remove_ca_cmd(self, dest_path: str, ca_content_escaped: str, use_sudo: bool) -> str:
        """Build the command to remove CA key from file."""
        if use_sudo:
            return (
                f"if [ -f {dest_path} ]; then "
                f"  sudo grep -vF '{ca_content_escaped}' {dest_path} > /tmp/ca.pub.tmp.$$ && "
                f"  sudo mv /tmp/ca.pub.tmp.$$ {dest_path} && "
                f"  sudo chmod 644 {dest_path} && "
                f"  sudo chown root:root {dest_path} && "
                f"  echo 'removed'; "
                f"else "
                f"  echo 'not_found'; "
                f"fi"
            )
        else:
            return (
                f"if [ -f {dest_path} ]; then "
                f"  grep -vF '{ca_content_escaped}' {dest_path} > /tmp/ca.pub.tmp.$$ && "
                f"  mv /tmp/ca.pub.tmp.$$ {dest_path} && "
                f"  chmod 644 {dest_path} && "
                f"  echo 'removed'; "
                f"else "
                f"  echo 'not_found'; "
                f"fi"
            )

    def _remove_ca_from_server(
        self,
        server: str,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        ca_content_escaped: str,
        use_sudo: bool,
        password: str,
        prompt_password: bool,
        restart_ssh: bool,
        restart_cmd: str,
    ) -> tuple[bool, str, str]:
        """Remove CA key from a single server."""
        print(f"Removing from {server}...", end=" ", flush=True)

        connection_addr = host_map.get(server, server)

        try:
            cmd_str = self._build_remove_ca_cmd(dest_path, ca_content_escaped, use_sudo)

            success, output, password = self._run_remote_cmd(
                connection_addr, ssh_user, cmd_str, password, prompt_password
            )

            if success:
                if "removed" in output:
                    print("✓ (removed)")
                elif "not_found" in output:
                    print("✓ (file not found)")
                else:
                    print("✓")

                if restart_ssh:
                    self._restart_ssh_service(
                        server,
                        connection_addr,
                        ssh_user,
                        password,
                        restart_cmd,
                        use_sudo,
                    )
                return True, output.strip(), password
            else:
                print(f"✗ ({output.strip()})")
                return False, output.strip(), password

        except Exception as e:
            print(f"✗ ({str(e)})")
            return False, str(e), password

    def _update_db_remove_deployment(self, removed_servers: list, ca_fingerprint: str):
        """Update database to remove servers from deployment tracking."""
        if not removed_servers:
            return

        db = self._load_db()

        # Ensure ca_deployments exists (for backward compatibility)
        if "ca_deployments" in db:
            # Find deployment record
            for deployment in db["ca_deployments"]:
                if deployment.get("fingerprint") == ca_fingerprint:
                    # Remove servers from the list
                    current_servers = set(deployment.get("servers", []))
                    current_servers.difference_update(removed_servers)
                    deployment["servers"] = sorted(current_servers)
                    deployment["last_updated"] = datetime.now().isoformat()
                    break

        self._save_db(db)

    def remove_ca(
        self,
        inventory_file: str,
        ssh_user: str = None,
        ca_path: str = "/etc/ssh/ca.pub",
        limit: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        Remove the CA public key from remote servers listed in inventory file.

        Args:
            inventory_file: Path to YAML inventory file
            ssh_user: SSH user (default: current user)
            ca_path: Path to CA file on remote servers
            limit: Limit to specific hosts/groups
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if all removals succeeded
        """
        result = self._validate_and_load_remove_ca(inventory_file, limit)
        if not result:
            return False
        inventory, servers, host_map, ca_fingerprint, ca_content_escaped = result

        # Get SSH user (prefer service account over root)
        if not ssh_user:
            ssh_user = inventory.get("ssh_user", os.environ.get("USER"))

        # Get destination path
        dest_path = inventory.get("ca_path", ca_path)

        # Check if we should use sudo
        use_sudo = inventory.get("use_sudo", True)

        print("=" * 70)
        print("REMOVING CA PUBLIC KEY FROM REMOTE SERVERS")
        print("=" * 70)
        print(f"CA Fingerprint: {ca_fingerprint}")
        print(f"CA File Path: {dest_path}")
        print(f"SSH User: {ssh_user}")
        print(f"Use sudo: {use_sudo}")
        print(f"Servers: {len(servers)}")
        print()

        success_count = 0
        failed_servers = []
        removed_servers = []

        # Get restart settings
        restart_ssh = inventory.get("restart_ssh", False)
        restart_cmd = inventory.get("restart_command", "systemctl reload sshd")

        # Track if we've prompted for password
        server_password = password

        for server in servers:
            success, output, server_password = self._remove_ca_from_server(
                server,
                host_map,
                ssh_user,
                dest_path,
                ca_content_escaped,
                use_sudo,
                server_password,
                prompt_password,
                restart_ssh,
                restart_cmd,
            )

            if success:
                success_count += 1
                if "removed" in output:
                    removed_servers.append(server)
            else:
                failed_servers.append((server, output))

        # Update database to remove servers from deployment tracking
        self._update_db_remove_deployment(removed_servers, ca_fingerprint)

        print()
        print("=" * 70)
        print(f"✅ Successfully removed from {success_count}/{len(servers)} servers")

        if failed_servers:
            print("❌ Failed servers:")
            for server, error in failed_servers:
                print(f"  - {server}: {error}")

        print("=" * 70)

        return len(failed_servers) == 0

    def _validate_and_load_list_ca(
        self, inventory_file: str, limit: str
    ) -> Optional[tuple[dict, list, dict, str, str]]:
        """Validate files and load inventory/CA content for list_ca_deployments."""
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return None

        if not self.ca_pub.exists():
            print(f"Error: CA public key not found: {self.ca_pub}", file=sys.stderr)
            return None

        # Get CA fingerprint for identification
        ca_fingerprint = self._get_ca_fingerprint()
        if not ca_fingerprint:
            print("Error: Could not get CA fingerprint", file=sys.stderr)
            return None

        # Load inventory
        inventory = self._load_inventory_file(inventory_file)
        if not inventory:
            return None

        # Get servers
        servers, host_map = self._get_servers_from_inventory(inventory, limit)
        if not servers:
            return None

        # Read the CA public key content
        try:
            with open(self.ca_pub, "r") as f:
                ca_key_content = f.read().strip()
        except Exception as e:
            print(f"Error reading CA public key: {e}", file=sys.stderr)
            return None

        # Escape single quotes in the key content for the shell command
        ca_key_escaped = ca_key_content.replace("'", "'\\''")

        return inventory, servers, host_map, ca_fingerprint, ca_key_escaped

    def _check_server_ca_status(
        self,
        server: str,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        ca_key_escaped: str,
        password: str,
        prompt_password: bool,
    ) -> tuple[str, str, str]:
        """Check CA deployment status on a single server."""
        # Get connection address (use ansible_host if available)
        connection_addr = host_map.get(server, server)

        # Check if CA exists on remote server
        cmd_str = (
            f"if [ -f {dest_path} ] && grep -qF '{ca_key_escaped}' {dest_path} 2>/dev/null; then "
            f"echo 'DEPLOYED'; "
            f"elif [ -f {dest_path} ]; then "
            f"echo 'FILE_EXISTS'; "
            f"else "
            f"echo 'NOT_FOUND'; "
            f"fi"
        )

        success, output, password = self._run_remote_cmd(
            connection_addr, ssh_user, cmd_str, password, prompt_password
        )

        status = output.strip()
        if success:
            return "SUCCESS", status, password
        else:
            return "FAILURE", status if status else "connection failed", password

    def _process_ca_deployment_checks(
        self,
        servers: list,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        ca_key_escaped: str,
        password: str,
        prompt_password: bool,
    ) -> tuple[list, list, list]:
        """Process deployment checks for a list of servers."""
        deployed = []
        not_deployed = []
        unreachable = []
        server_password = password

        for server in servers:
            status_type, status_msg, server_password = self._check_server_ca_status(
                server,
                host_map,
                ssh_user,
                dest_path,
                ca_key_escaped,
                server_password,
                prompt_password,
            )

            if status_type == "SUCCESS":
                if "DEPLOYED" in status_msg:
                    deployed.append(server)
                elif "FILE_EXISTS" in status_msg:
                    not_deployed.append((server, "CA file exists but this CA not found"))
                else:
                    not_deployed.append((server, "CA file not found"))
            else:
                unreachable.append((server, status_msg))

        return deployed, not_deployed, unreachable

    def _display_ca_deployment_results(
        self, deployed: list, not_deployed: list, unreachable: list, total: int
    ) -> None:
        """Display the results of the CA deployment check."""
        print("=" * 70)
        print("RESULTS")
        print("=" * 70)
        print()

        if deployed:
            print(f"✅ DEPLOYED ({len(deployed)}):")
            for server in deployed:
                print(f"  ✓ {server}")
            print()

        if not_deployed:
            print(f"❌ NOT DEPLOYED ({len(not_deployed)}):")
            for server, reason in not_deployed:
                print(f"  ✗ {server}: {reason}")
            print()

        if unreachable:
            print(f"⚠️  UNREACHABLE ({len(unreachable)}):")
            for server, reason in unreachable:
                print(f"  ? {server}: {reason}")
            print()

        # Summary
        print("=" * 70)
        print(
            f"Summary: {len(deployed)}/{total} deployed, "
            f"{len(not_deployed)}/{total} not deployed, "
            f"{len(unreachable)}/{total} unreachable"
        )
        print("=" * 70)

    def list_ca_deployments(
        self,
        inventory_file: str,
        ssh_user: str = None,
        ca_path: str = "/etc/ssh/ca.pub",
        limit: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        List CA deployment status for servers in inventory.

        Args:
            inventory_file: Path to YAML inventory file
            ssh_user: SSH user (default: current user)
            ca_path: Path to CA file on remote servers
            limit: Limit to specific hosts/groups
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if all checks succeeded
        """
        result = self._validate_and_load_list_ca(inventory_file, limit)
        if not result:
            return False
        inventory, servers, host_map, ca_fingerprint, ca_key_escaped = result

        # Get SSH user (prefer service account over root)
        if not ssh_user:
            ssh_user = inventory.get("ssh_user", os.environ.get("USER"))

        # Get destination path
        dest_path = inventory.get("ca_path", ca_path)

        print("=" * 70)
        print("CA DEPLOYMENT STATUS")
        print("=" * 70)
        print(f"CA Fingerprint: {ca_fingerprint}")
        print(f"CA File Path: {dest_path}")
        print(f"SSH User: {ssh_user}")
        print(f"Checking {len(servers)} server(s)")
        print()

        # Check each server
        deployed, not_deployed, unreachable = self._process_ca_deployment_checks(
            servers,
            host_map,
            ssh_user,
            dest_path,
            ca_key_escaped,
            password,
            prompt_password,
        )

        # Display results
        self._display_ca_deployment_results(deployed, not_deployed, unreachable, len(servers))

        return len(unreachable) == 0

    def _validate_and_load_list_krl(
        self, inventory_file: str, limit: str
    ) -> Optional[tuple[dict, list, dict, str]]:
        """Validate files and load inventory/KRL content for list_krl_deployments."""
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            print(f"Error: Inventory file not found: {inventory_file}", file=sys.stderr)
            return None

        if not self.krl_file.exists():
            print(f"Error: KRL file not found: {self.krl_file}", file=sys.stderr)
            return None

        # Get local KRL checksum
        try:
            with open(self.krl_file, "rb") as f:
                local_krl_md5 = hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            print(f"Error calculating local KRL checksum: {e}", file=sys.stderr)
            return None

        # Load inventory
        inventory = self._load_inventory_file(inventory_file)
        if not inventory:
            return None

        # Get servers
        servers, host_map = self._get_servers_from_inventory(inventory, limit)
        if not servers:
            return None

        return inventory, servers, host_map, local_krl_md5

    def _check_server_krl_status(
        self,
        server: str,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        local_krl_md5: str,
        password: str,
        prompt_password: bool,
    ) -> tuple[str, str, str]:
        """Check KRL deployment status on a single server."""
        # Get connection address (use ansible_host if available)
        connection_addr = host_map.get(server, server)

        # Check KRL checksum on remote server
        cmd_str = (
            f"if [ -f {dest_path} ]; then "
            f"md5sum {dest_path} | cut -d' ' -f1; "
            f"else "
            f"echo 'NOT_FOUND'; "
            f"fi"
        )

        success, output, password = self._run_remote_cmd(
            connection_addr, ssh_user, cmd_str, password, prompt_password
        )

        status = output.strip()
        if success:
            if status == local_krl_md5:
                # DEPLOYED
                return "SUCCESS", "DEPLOYED", password
            elif status == "NOT_FOUND":
                return "SUCCESS", "NOT_FOUND", password
            else:
                # Outdated or corrupted
                return "SUCCESS", f"Checksum mismatch (Remote: {status[:8]}...)", password
        else:
            return "FAILURE", status if status else "connection failed", password

    def _process_krl_deployment_checks(
        self,
        servers: list,
        host_map: dict,
        ssh_user: str,
        dest_path: str,
        local_krl_md5: str,
        password: str,
        prompt_password: bool,
    ) -> tuple[list, list, list, list]:
        """Process KRL deployment checks for a list of servers."""
        deployed = []
        outdated = []
        not_deployed = []
        unreachable = []
        server_password = password

        for server in servers:
            status_type, status_msg, server_password = self._check_server_krl_status(
                server,
                host_map,
                ssh_user,
                dest_path,
                local_krl_md5,
                server_password,
                prompt_password,
            )

            if status_type == "SUCCESS":
                if status_msg == "DEPLOYED":
                    deployed.append(server)
                elif status_msg == "NOT_FOUND":
                    not_deployed.append((server, "KRL file not found"))
                else:
                    outdated.append((server, status_msg))
            else:
                unreachable.append((server, status_msg))

        return deployed, outdated, not_deployed, unreachable

    def _display_krl_deployment_results(
        self, deployed: list, outdated: list, not_deployed: list, unreachable: list, total: int
    ) -> None:
        """Display the results of the KRL deployment check."""
        print("=" * 70)
        print("RESULTS")
        print("=" * 70)
        print()

        if deployed:
            print(f"✅ DEPLOYED ({len(deployed)}):")
            for server in deployed:
                print(f"  ✓ {server}")
            print()

        if outdated:
            print(f"⚠️  OUTDATED ({len(outdated)}):")
            for server, reason in outdated:
                print(f"  ? {server}: {reason}")
            print()

        if not_deployed:
            print(f"❌ NOT DEPLOYED ({len(not_deployed)}):")
            for server, reason in not_deployed:
                print(f"  ✗ {server}: {reason}")
            print()

        if unreachable:
            print(f"⚠️  UNREACHABLE ({len(unreachable)}):")
            for server, reason in unreachable:
                print(f"  ? {server}: {reason}")
            print()

        # Summary
        print("=" * 70)
        print(
            f"Summary: {len(deployed)}/{total} deployed, "
            f"{len(outdated)}/{total} outdated, "
            f"{len(not_deployed)}/{total} not deployed, "
            f"{len(unreachable)}/{total} unreachable"
        )
        print("=" * 70)

    def list_krl_deployments(
        self,
        inventory_file: str,
        ssh_user: str = None,
        krl_path: str = "/etc/ssh/revoked_keys.krl",
        limit: str = None,
        password: str = None,
        prompt_password: bool = False,
    ) -> bool:
        """
        List KRL deployment status for servers in inventory.

        Args:
            inventory_file: Path to YAML inventory file
            ssh_user: SSH user (default: current user)
            krl_path: Path to KRL file on remote servers
            limit: Limit to specific hosts/groups
            password: SSH password (optional, for password auth)
            prompt_password: Whether to prompt for password if key auth fails

        Returns:
            True if all checks succeeded
        """
        result = self._validate_and_load_list_krl(inventory_file, limit)
        if not result:
            return False
        inventory, servers, host_map, local_krl_md5 = result

        # Get SSH user
        if not ssh_user:
            ssh_user = inventory.get("ssh_user", os.environ.get("USER"))

        # Get destination path
        dest_path = inventory.get("krl_path", krl_path)

        print("=" * 70)
        print("KRL DEPLOYMENT STATUS")
        print("=" * 70)
        print(f"Local KRL MD5: {local_krl_md5}")
        print(f"KRL File Path: {dest_path}")
        print(f"SSH User: {ssh_user}")
        print(f"Checking {len(servers)} server(s)")
        print()

        # Check each server
        deployed, outdated, not_deployed, unreachable = self._process_krl_deployment_checks(
            servers, host_map, ssh_user, dest_path, local_krl_md5, password, prompt_password
        )

        # Display results
        self._display_krl_deployment_results(
            deployed, outdated, not_deployed, unreachable, len(servers)
        )

        return len(unreachable) == 0 and len(outdated) == 0

    def show_info(self):
        """Show CA information."""
        if not self.config_file.exists():
            print("Error: CA not initialized", file=sys.stderr)
            return

        with open(self.config_file, "r") as f:
            config = json.load(f)

        db = self._load_db()

        print("=" * 70)
        print("SSH CERTIFICATE AUTHORITY INFORMATION")
        print("=" * 70)
        print(f"Name: {config['name']}")
        print(f"Created: {config['created']}")
        print(f"Key Type: {config['key_type']}")
        print(f"CA Directory: {self.ca_dir.absolute()}")
        print()
        print(f"Total Certificates Signed: {len(db['certificates'])}")
        print(f"Active Certificates: {sum(1 for c in db['certificates'] if not c['revoked'])}")
        print(f"Revoked Certificates: {sum(1 for c in db['certificates'] if c['revoked'])}")
        print(f"Next Serial Number: {db['next_serial']}")
        print()
        print("Files:")
        print(f"  CA Private Key: {self.ca_key}")
        print(f"  CA Public Key: {self.ca_pub}")
        print(f"  Certificate DB: {self.db_file}")
        print(f"  KRL File: {self.krl_file}")
        print("=" * 70)


def _create_argument_parser():
    """Create and configure the argument parser."""
    # Get default CA directory from environment or use ~/.sshca
    default_ca_dir = os.path.expanduser(os.environ.get("SSHCA_DIR", "~/.sshca"))

    parser = argparse.ArgumentParser(
        description="SSH Certificate Authority Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  SSHCA_DIR    Default CA directory (default: ~/.sshca)
        """,
    )

    parser.add_argument(
        "--ca-dir",
        default=default_ca_dir,
        help=f"CA directory (default: $SSHCA_DIR or ~/.sshca, currently: {default_ca_dir})",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize a new SSH CA")
    init_parser.add_argument("--name", required=True, help="Name of the CA")
    init_parser.add_argument(
        "--key-type",
        default="ed25519",
        choices=["ed25519", "rsa", "ecdsa"],
        help="Key type (default: ed25519)",
    )
    init_parser.add_argument("--comment", help="Key comment")
    init_parser.add_argument("--passphrase", help="Passphrase to encrypt CA private key")
    init_parser.add_argument(
        "--prompt-passphrase",
        action="store_true",
        help="Prompt for passphrase to encrypt CA private key",
    )

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a public key")
    sign_parser.add_argument("--public-key", required=True, help="Path to public key file")
    sign_parser.add_argument(
        "--identity", required=True, help="Key identity (e.g., user@example.com)"
    )
    sign_parser.add_argument(
        "--principals", required=True, help="Comma-separated list of principals"
    )
    sign_parser.add_argument(
        "--validity",
        default="+52w",
        help=(
            "Validity period (default: +52w). "
            "Supports: 1d, 1w, 1m, 1y, or ssh-keygen format (+52w)"
        ),
    )
    sign_parser.add_argument(
        "--type", default="user", choices=["user", "host"], help="Certificate type (default: user)"
    )
    sign_parser.add_argument("--options", help="Comma-separated list of options")
    sign_parser.add_argument("--output", help="Output certificate file")

    # Sign remote command
    sign_remote_parser = subparsers.add_parser(
        "sign-remote", help="Sign a public key on a remote server"
    )
    sign_remote_parser.add_argument(
        "--server", required=True, help="Remote server (hostname or IP)"
    )
    sign_remote_parser.add_argument(
        "--remote-key", required=True, help="Path to public key on remote server"
    )
    sign_remote_parser.add_argument(
        "--identity", required=True, help="Key identity (e.g., user@example.com)"
    )
    sign_remote_parser.add_argument(
        "--principals", required=True, help="Comma-separated list of principals"
    )
    sign_remote_parser.add_argument(
        "--validity",
        default="+52w",
        help="Validity period (default: +52w). Supports: 1d, 1w, 1m, 1y",
    )
    sign_remote_parser.add_argument(
        "--type", default="user", choices=["user", "host"], help="Certificate type (default: user)"
    )
    sign_remote_parser.add_argument("--options", help="Comma-separated list of options")
    sign_remote_parser.add_argument(
        "--ssh-user", help="SSH user for connecting (default: current user)"
    )
    sign_remote_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    sign_remote_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List all certificates")
    list_parser.add_argument("--all", action="store_true", help="Include revoked certificates")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke a certificate")
    revoke_parser.add_argument("--serial", type=int, required=True, help="Serial number to revoke")
    revoke_parser.add_argument("--reason", help="Reason for revocation")

    # Update KRL command
    subparsers.add_parser("update-krl", help="Update the Key Revocation List")

    # Push KRL command
    push_parser = subparsers.add_parser("push-krl", help="Push KRL to remote servers")
    push_parser.add_argument("--inventory", required=True, help="Path to inventory YAML file")
    push_parser.add_argument(
        "--ssh-user", help="SSH user (default: from inventory or current user)"
    )
    push_parser.add_argument(
        "--krl-path",
        default="/etc/ssh/revoked_keys.krl",
        help="Destination path on remote servers (default: /etc/ssh/revoked_keys.krl)",
    )
    push_parser.add_argument(
        "--limit", "-l", help="Limit to specific hosts (comma-separated, supports wildcards)"
    )
    push_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    push_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # Push CA command
    push_ca_parser = subparsers.add_parser("push-ca", help="Push CA public key to remote servers")
    push_ca_parser.add_argument("--inventory", required=True, help="Path to inventory YAML file")
    push_ca_parser.add_argument(
        "--ssh-user", help="SSH user (default: from inventory or current user)"
    )
    push_ca_parser.add_argument(
        "--ca-path",
        default="/etc/ssh/ca.pub",
        help="Destination path on remote servers (default: /etc/ssh/ca.pub)",
    )
    push_ca_parser.add_argument(
        "--limit", "-l", help="Limit to specific hosts (comma-separated, supports wildcards)"
    )
    push_ca_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    push_ca_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # Remove CA command
    remove_ca_parser = subparsers.add_parser(
        "remove-ca", help="Remove CA public key from remote servers"
    )
    remove_ca_parser.add_argument("--inventory", required=True, help="Path to inventory YAML file")
    remove_ca_parser.add_argument(
        "--ssh-user", help="SSH user (default: from inventory or current user)"
    )
    remove_ca_parser.add_argument(
        "--ca-path",
        default="/etc/ssh/ca.pub",
        help="Path to CA file on remote servers (default: /etc/ssh/ca.pub)",
    )
    remove_ca_parser.add_argument(
        "--limit", "-l", help="Limit to specific hosts (comma-separated, supports wildcards)"
    )
    remove_ca_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    remove_ca_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # List CA deployments command
    list_ca_parser = subparsers.add_parser(
        "list-ca-deployments", help="List CA deployment status on remote servers"
    )
    list_ca_parser.add_argument("--inventory", required=True, help="Path to inventory YAML file")
    list_ca_parser.add_argument(
        "--ssh-user", help="SSH user (default: from inventory or current user)"
    )
    list_ca_parser.add_argument(
        "--ca-path",
        default="/etc/ssh/ca.pub",
        help="Path to CA file on remote servers (default: /etc/ssh/ca.pub)",
    )
    list_ca_parser.add_argument(
        "--limit", "-l", help="Limit to specific hosts (comma-separated, supports wildcards)"
    )
    list_ca_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    list_ca_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # List KRL deployments command
    list_krl_parser = subparsers.add_parser(
        "list-krl-deployments", help="List KRL deployment status on remote servers"
    )
    list_krl_parser.add_argument("--inventory", required=True, help="Path to inventory YAML file")
    list_krl_parser.add_argument(
        "--ssh-user", help="SSH user (default: from inventory or current user)"
    )
    list_krl_parser.add_argument(
        "--krl-path",
        default="/etc/ssh/revoked_keys.krl",
        help="Destination path on remote servers (default: /etc/ssh/revoked_keys.krl)",
    )
    list_krl_parser.add_argument(
        "--limit", "-l", help="Limit to specific hosts (comma-separated, supports wildcards)"
    )
    list_krl_parser.add_argument("--password", help="SSH password (optional, for password auth)")
    list_krl_parser.add_argument(
        "--prompt-password", action="store_true", help="Prompt for password if SSH key auth fails"
    )

    # Info command
    subparsers.add_parser("info", help="Show CA information")

    return parser


def _execute_signing_command(args, ca) -> Optional[int]:
    """Execute signing-related commands."""
    if args.command == "sign":
        principals = [p.strip() for p in args.principals.split(",")]
        options = [o.strip() for o in args.options.split(",")] if args.options else None
        success = ca.sign_key(
            args.public_key,
            args.identity,
            principals,
            args.validity,
            args.type,
            options,
            args.output,
        )
        return 0 if success else 1

    elif args.command == "sign-remote":
        principals = [p.strip() for p in args.principals.split(",")]
        options = [o.strip() for o in args.options.split(",")] if args.options else None
        success = ca.sign_remote_key(
            args.server,
            args.remote_key,
            args.identity,
            principals,
            args.validity,
            args.type,
            options,
            args.ssh_user,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    return None


def _execute_deployment_command(args, ca) -> Optional[int]:
    """Execute deployment-related commands."""
    if args.command == "push-krl":
        success = ca.push_krl(
            args.inventory,
            args.ssh_user,
            args.krl_path,
            args.limit,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    elif args.command == "push-ca":
        success = ca.push_ca(
            args.inventory,
            args.ssh_user,
            args.ca_path,
            args.limit,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    elif args.command == "remove-ca":
        success = ca.remove_ca(
            args.inventory,
            args.ssh_user,
            args.ca_path,
            args.limit,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    elif args.command == "list-ca-deployments":
        success = ca.list_ca_deployments(
            args.inventory,
            args.ssh_user,
            args.ca_path,
            args.limit,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    elif args.command == "list-krl-deployments":
        success = ca.list_krl_deployments(
            args.inventory,
            args.ssh_user,
            args.krl_path,
            args.limit,
            args.password,
            args.prompt_password,
        )
        return 0 if success else 1

    return None


def _execute_command(args, ca):
    """Execute the command."""
    if args.command == "init":
        success = ca.init_ca(
            args.name, args.key_type, args.comment, args.passphrase, args.prompt_passphrase
        )
        return 0 if success else 1

    # Check signing commands
    result = _execute_signing_command(args, ca)
    if result is not None:
        return result

    # Check deployment commands
    result = _execute_deployment_command(args, ca)
    if result is not None:
        return result

    if args.command == "list":
        ca.list_certificates(show_revoked=args.all)
        return 0

    elif args.command == "revoke":
        success = ca.revoke_certificate(args.serial, args.reason)
        return 0 if success else 1

    elif args.command == "update-krl":
        success = ca.update_krl()
        return 0 if success else 1

    elif args.command == "info":
        ca.show_info()
        return 0

    return 0


def main():
    """Main entry point."""
    parser = _create_argument_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Create CA instance
    ca = SSHCA(ca_dir=args.ca_dir)
    return _execute_command(args, ca)


if __name__ == "__main__":
    sys.exit(main())
