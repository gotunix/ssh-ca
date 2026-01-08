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
SSH CA Certificate Report Generator

Generates email reports from SSH CA certificate data.
Includes active, expired, and revoked certificate summaries.

Usage:
    # Send report via email (uses default CA at ~/.sshca/default/)
    ssh-ca-report --email recipient@example.com

    # Generate HTML report to file for specific CA
    ssh-ca-report --ca-dir ~/.sshca/prod-ca --output report.html

    # Send to multiple recipients with custom SMTP
    ssh-ca-report --ca-dir ~/.sshca/prod-ca --email user1@example.com,user2@example.com \\
                           --smtp-host smtp.gmail.com --smtp-port 587 --smtp-user your@email.com

    # Include live deployment status (inventory from ~/.sshca/inventory/)
    ssh-ca-report --inventory production.yaml --output report.html

Environment Variables:
    SSHCA_DIR    Default CA directory (default: ~/.sshca)
                 Example: export SSHCA_DIR=/etc/ssh-ca
"""

import argparse
import json
import os
import smtplib
import sys
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, Template


class SSHCAReporter:
    """Generate reports from SSH CA certificate database."""

    def __init__(self, ca_dir: str = "./ssh-ca"):
        """
        Initialize the reporter.

        Args:
            ca_dir: Directory containing SSH CA files
        """
        self.ca_dir = Path(ca_dir)
        self.db_file = self.ca_dir / "certificates.json"
        self.config_file = self.ca_dir / "ca_config.json"

    def _load_db(self) -> Dict:
        """Load the certificate database."""
        if not self.db_file.exists():
            print(f"Error: Certificate database not found: {self.db_file}", file=sys.stderr)
            sys.exit(1)

        with open(self.db_file, "r") as f:
            return json.load(f)

    def _load_config(self) -> Dict:
        """Load CA configuration."""
        if not self.config_file.exists():
            return {}

        with open(self.config_file, "r") as f:
            return json.load(f)

    def _is_certificate_expired(self, cert: dict) -> bool:
        """Check if a certificate is expired."""
        try:
            import re

            validity = cert.get("validity", "")
            signed_at = datetime.fromisoformat(cert["signed_at"])

            # Parse validity
            match = re.match(r"^\+?(\d+)([smhdwMy])$", validity)
            if not match:
                return False

            value = int(match.group(1))
            unit = match.group(2)

            # Convert to timedelta
            if unit == "M":
                value = value * 4
                unit = "w"
            elif unit == "y":
                value = value * 52
                unit = "w"

            unit_map = {
                "s": timedelta(seconds=value),
                "m": timedelta(minutes=value),
                "h": timedelta(hours=value),
                "d": timedelta(days=value),
                "w": timedelta(weeks=value),
            }

            expiration = signed_at + unit_map.get(unit, timedelta(0))
            return datetime.now() > expiration

        except Exception:
            return False

    def _get_expiration_date(self, cert: dict) -> str:
        """Get the expiration date of a certificate."""
        try:
            import re

            validity = cert.get("validity", "")
            signed_at = datetime.fromisoformat(cert["signed_at"])

            match = re.match(r"^\+?(\d+)([smhdwMy])$", validity)
            if not match:
                return "Unknown"

            value = int(match.group(1))
            unit = match.group(2)

            if unit == "M":
                value = value * 4
                unit = "w"
            elif unit == "y":
                value = value * 52
                unit = "w"

            unit_map = {
                "s": timedelta(seconds=value),
                "m": timedelta(minutes=value),
                "h": timedelta(hours=value),
                "d": timedelta(days=value),
                "w": timedelta(weeks=value),
            }

            expiration = signed_at + unit_map.get(unit, timedelta(0))
            return expiration.strftime("%Y-%m-%d %H:%M")

        except Exception:
            return "Unknown"

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

        # Merge, but don't override existing entries
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

    def _extract_servers_from_inventory(self, inventory: dict) -> list:
        """
        Extract server list from inventory dictionary.

        Args:
            inventory: Inventory dictionary

        Returns:
            List of server hostnames
        """
        servers = []

        # Check for simple servers list (backward compatibility)
        if "servers" in inventory and isinstance(inventory["servers"], list):
            servers = inventory["servers"]

        # Check for Ansible-style groups
        elif "all" in inventory:
            host_map = self._parse_ansible_inventory(inventory)
            servers = list(host_map.keys())

        # Check for custom groups format
        elif "groups" in inventory:
            for group_servers in inventory["groups"].values():
                if isinstance(group_servers, list):
                    servers.extend(group_servers)
            servers = list(set(servers))

        return servers

    def _load_inventory_data(self, inventory_file: str) -> tuple[dict, list]:
        """Load inventory file and extract servers."""
        if not inventory_file:
            return {}, []

        # Resolve inventory path
        inventory_path = self._resolve_inventory_path(inventory_file)

        if not inventory_path.exists():
            return {}, []

        try:
            import yaml

            with open(inventory_path, "r") as f:
                inventory = yaml.safe_load(f)
        except Exception:
            return {}, []

        # Extract servers
        servers = self._extract_servers_from_inventory(inventory)

        return inventory, servers

    def _verify_ca_on_server(
        self, server: str, ssh_user: str, ca_path: str, ca_key_escaped: str
    ) -> str:
        """Check if CA is deployed on a single server."""
        import subprocess

        check_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "BatchMode=yes",
            f"{ssh_user}@{server}",
            f"if [ -f {ca_path} ] && grep -qF '{ca_key_escaped}' {ca_path} 2>/dev/null; "
            "then echo 'DEPLOYED'; else echo 'NOT_DEPLOYED'; fi",
        ]

        try:
            proc = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)

            if proc.returncode == 0:
                if "DEPLOYED" in proc.stdout:
                    return "DEPLOYED"
                else:
                    return "NOT_DEPLOYED"
            else:
                return "UNREACHABLE"
        except (subprocess.TimeoutExpired, Exception):
            return "UNREACHABLE"

    def _process_tracked_deployments(self, deployments: list, result: dict) -> None:
        """Process tracked deployments from database."""
        if not deployments:
            return

        for deployment in deployments:
            servers = deployment.get("servers", [])
            result["tracked_servers"].extend(servers)
            result["deployment_count"] = len(set(result["tracked_servers"]))

            last_updated = deployment.get("last_updated")
            if last_updated and (
                not result["last_deployed"] or last_updated > result["last_deployed"]
            ):
                result["last_deployed"] = last_updated

    def _perform_live_ca_check(self, inventory_file: str, ca_pub: Path, result: dict) -> None:
        """Perform live CA deployment check."""
        import os

        # Read CA key content
        try:
            with open(ca_pub, "r") as f:
                ca_key_content = f.read().strip()
            ca_key_escaped = ca_key_content.replace("'", "'\\''")
        except Exception:
            return

        # Load inventory
        inventory, servers = self._load_inventory_data(inventory_file)
        if not servers:
            return

        # Get SSH user and CA path
        ssh_user = inventory.get("ssh_user", os.environ.get("USER"))
        ca_path = inventory.get("ca_path", "/etc/ssh/ca.pub")

        result["live_check_performed"] = True

        # Check each server (limit to 10 for performance)
        for server in servers[:10]:
            status = self._verify_ca_on_server(server, ssh_user, ca_path, ca_key_escaped)

            if status == "DEPLOYED":
                result["deployed"].append(server)
            elif status == "NOT_DEPLOYED":
                result["not_deployed"].append(server)
            else:
                result["unreachable"].append(server)

    def _check_ca_deployments(self, inventory_file: str = None) -> Dict:
        """
        Check CA deployment status.

        Args:
            inventory_file: Optional path to inventory file for live checking

        Returns:
            Dict with deployment status information
        """
        db = self._load_db()
        ca_pub = self.ca_dir / "ca.pub"

        result = {
            "tracked_servers": [],
            "deployment_count": 0,
            "last_deployed": None,
            "live_check_performed": False,
            "deployed": [],
            "not_deployed": [],
            "unreachable": [],
        }

        # Get deployment info from database
        self._process_tracked_deployments(db.get("ca_deployments", []), result)

        # Perform live check if inventory provided
        if inventory_file:
            inventory_path = self._resolve_inventory_path(inventory_file)
            if inventory_path.exists() and ca_pub.exists():
                self._perform_live_ca_check(str(inventory_path), ca_pub, result)

        return result

    def _verify_krl_on_server(
        self, server: str, ssh_user: str, krl_path: str, local_krl_md5: str
    ) -> str:
        """Check if KRL is deployed on a single server."""
        import subprocess

        check_cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "BatchMode=yes",
            f"{ssh_user}@{server}",
            f"if [ -f {krl_path} ]; then md5sum {krl_path} | cut -d' ' -f1; "
            "else echo 'NOT_FOUND'; fi",
        ]

        try:
            proc = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)

            if proc.returncode == 0:
                status = proc.stdout.strip()
                if status == local_krl_md5:
                    return "DEPLOYED"
                elif status == "NOT_FOUND":
                    return "NOT_DEPLOYED"
                else:
                    return "OUTDATED"
            else:
                return "UNREACHABLE"
        except (subprocess.TimeoutExpired, Exception):
            return "UNREACHABLE"

    def _perform_live_krl_check(self, inventory_file: str, krl_file: Path, result: dict) -> None:
        """Perform live KRL deployment check."""
        import hashlib
        import os

        # Calculate local KRL checksum
        try:
            with open(krl_file, "rb") as f:
                local_krl_md5 = hashlib.md5(f.read()).hexdigest()
        except Exception:
            return

        # Load inventory
        inventory, servers = self._load_inventory_data(inventory_file)
        if not servers:
            return

        # Get SSH user and KRL path
        ssh_user = inventory.get("ssh_user", os.environ.get("USER"))
        krl_path = inventory.get("krl_path", "/etc/ssh/revoked_keys.krl")

        result["live_check_performed"] = True

        # Check each server (limit to 10 for performance)
        for server in servers[:10]:
            status = self._verify_krl_on_server(server, ssh_user, krl_path, local_krl_md5)

            if status == "DEPLOYED":
                result["deployed"].append(server)
            elif status == "NOT_DEPLOYED":
                result["not_deployed"].append(server)
            elif status == "OUTDATED":
                result["outdated"].append(server)
            else:
                result["unreachable"].append(server)

    def _check_krl_deployments(self, inventory_file: str = None) -> Dict:
        """
        Check KRL deployment status.

        Args:
            inventory_file: Optional path to inventory file for live checking

        Returns:
            Dict with deployment status information
        """
        db = self._load_db()
        krl_file = self.ca_dir / "revoked_keys.krl"

        result = {
            "tracked_servers": [],
            "deployment_count": 0,
            "last_deployed": None,
            "live_check_performed": False,
            "deployed": [],
            "outdated": [],
            "not_deployed": [],
            "unreachable": [],
        }

        # Get deployment info from database
        self._process_tracked_deployments(db.get("krl_deployments", []), result)

        # Perform live check if inventory provided
        if inventory_file:
            inventory_path = self._resolve_inventory_path(inventory_file)
            if inventory_path.exists() and krl_file.exists():
                self._perform_live_krl_check(str(inventory_path), krl_file, result)

        return result

    def generate_report_data(self, inventory_file: str = None) -> Dict:
        """Generate report data from certificate database."""
        db = self._load_db()
        config = self._load_config()

        # Categorize certificates
        active = []
        expired = []
        revoked = []
        expiring_soon = []  # Within 7 days

        for cert in db["certificates"]:
            if cert["revoked"]:
                revoked.append(cert)
            elif self._is_certificate_expired(cert):
                expired.append(cert)
            else:
                active.append(cert)

                # Check if expiring soon
                try:
                    exp_date_str = self._get_expiration_date(cert)
                    if exp_date_str != "Unknown":
                        exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d %H:%M")
                        days_until_expiry = (exp_date - datetime.now()).days
                        if 0 < days_until_expiry <= 7:
                            expiring_soon.append(cert)
                except Exception:
                    pass

        # Get CA deployment status
        ca_deployment_status = self._check_ca_deployments(inventory_file)

        # Get KRL deployment status
        krl_deployment_status = self._check_krl_deployments(inventory_file)

        return {
            "ca_name": db.get("ca_name", "SSH CA"),
            "ca_created": config.get("created", "Unknown"),
            "ca_encrypted": config.get("encrypted", False),
            "total": len(db["certificates"]),
            "active": active,
            "expired": expired,
            "revoked": revoked,
            "expiring_soon": expiring_soon,
            "ca_deployment": ca_deployment_status,
            "krl_deployment": krl_deployment_status,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def generate_html_report(self, data: Dict) -> str:
        """Generate HTML report using Jinja2 template."""

        # Prepare certificate data with formatted fields
        def format_cert(cert):
            """Format certificate data for template."""
            principals = ", ".join(cert["principals"][:3])
            if len(cert["principals"]) > 3:
                principals += "..."

            return {
                **cert,
                "principals_display": principals,
                "signed_date": datetime.fromisoformat(cert["signed_at"]).strftime("%Y-%m-%d %H:%M"),
                "expiration_date": self._get_expiration_date(cert),
                "revoked_date": (
                    datetime.fromisoformat(cert["revoked_at"]).strftime("%Y-%m-%d %H:%M")
                    if cert.get("revoked_at")
                    else "Unknown"
                ),
                "revocation_reason": cert.get("revocation_reason", "Not specified"),
            }

        template_data = {
            **data,
            "active": [format_cert(c) for c in data["active"]],
            "expired": [format_cert(c) for c in data["expired"]],
            "revoked": [format_cert(c) for c in data["revoked"]],
            "expiring_soon": [format_cert(c) for c in data["expiring_soon"]],
        }

        # Try to use Jinja2 template
        # Check multiple locations for template:
        # 1. ~/.sshca/reports/sshca_report_template.html (user custom)
        # 2. Package directory (bundled template)
        user_template_dir = Path.home() / ".sshca" / "reports"
        user_template_file = user_template_dir / "sshca_report_template.html"
        package_template_file = Path(__file__).parent / "sshca_report_template.html"

        if user_template_file.exists():
            # Load user custom template
            env = Environment(loader=FileSystemLoader(str(user_template_dir)))
            template = env.get_template("sshca_report_template.html")
            return template.render(**template_data)
        elif package_template_file.exists():
            # Load bundled template from package
            env = Environment(loader=FileSystemLoader(str(package_template_file.parent)))
            template = env.get_template(package_template_file.name)
            return template.render(**template_data)
        else:
            # Use inline template as final fallback
            template = Template(self._get_inline_template())
            return template.render(**template_data)

    def _get_inline_template(self) -> str:
        """Get inline Jinja2 template as fallback."""
        return """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { margin: 0 0 10px 0; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }
        .summary-card .number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .active { color: #10b981; }
        .expired { color: #ef4444; }
        .revoked { color: #f59e0b; }
        .expiring { color: #f59e0b; }
        .section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            margin-top: 0;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th {
            background-color: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        td { padding: 10px 12px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background-color: #f8f9fa; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-warning { background-color: #fef3c7; color: #92400e; }
        .badge-expired { background-color: #fee2e2; color: #991b1b; }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
        }
        .no-data {
            text-align: center;
            color: #999;
            padding: 20px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SSH Certificate Authority Report</h1>
        <p><strong>CA Name:</strong> {{ ca_name }}</p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        <p>
            <strong>Encryption:</strong>
            {% if ca_encrypted %}🔒 Enabled{% else %}🔓 Disabled{% endif %}
        </p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Total Certificates</h3>
            <div class="number">{{ total }}</div>
        </div>
        <div class="summary-card">
            <h3>Active</h3>
            <div class="number active">{{ active|length }}</div>
        </div>
        <div class="summary-card">
            <h3>Expired</h3>
            <div class="number expired">{{ expired|length }}</div>
        </div>
        <div class="summary-card">
            <h3>Revoked</h3>
            <div class="number revoked">{{ revoked|length }}</div>
        </div>
        <div class="summary-card">
            <h3>Expiring Soon</h3>
            <div class="number expiring">{{ expiring_soon|length }}</div>
            <small>(within 7 days)</small>
        </div>
    </div>

    {% if ca_deployment.deployment_count > 0 or ca_deployment.live_check_performed %}
    <div class="section">
        <h2>📡 CA Deployment Status</h2>
        {% if ca_deployment.deployment_count > 0 %}
        <p>
            <strong>Tracked Deployments:</strong>
            {{ ca_deployment.deployment_count }} server(s)
        </p>
        {% if ca_deployment.last_deployed %}
        <p>
            <strong>Last Deployed:</strong>
            {{ ca_deployment.last_deployed[:19] }}
        </p>
        {% endif %}
        {% endif %}

        {% if ca_deployment.live_check_performed %}
        <p>
            <strong>Live Check:</strong> Performed on
            {{ ca_deployment.deployed|length +
               ca_deployment.not_deployed|length +
               ca_deployment.unreachable|length }}
            server(s)
        </p>
        <table>
            <tr><th>Server</th><th>Status</th></tr>
            {% for server in ca_deployment.deployed %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge" style="background-color: #d1fae5; color: #065f46;">
                    ✓ Deployed
                </span></td>
            </tr>
            {% endfor %}
            {% for server in ca_deployment.not_deployed %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge badge-expired">✗ Not Deployed</span></td>
            </tr>
            {% endfor %}
            {% for server in ca_deployment.unreachable %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge badge-warning">? Unreachable</span></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p style="color: #666; font-style: italic;">
            No live check performed. Use --inventory to enable live checking.
        </p>
        {% endif %}
    </div>
    {% endif %}

    {% if krl_deployment.deployment_count > 0 or krl_deployment.live_check_performed %}
    <div class="section">
        <h2>🚫 KRL Deployment Status</h2>
        {% if krl_deployment.deployment_count > 0 %}
        <p>
            <strong>Tracked Deployments:</strong>
            {{ krl_deployment.deployment_count }} server(s)
        </p>
        {% if krl_deployment.last_deployed %}
        <p>
            <strong>Last Deployed:</strong>
            {{ krl_deployment.last_deployed[:19] }}
        </p>
        {% endif %}
        {% endif %}

        {% if krl_deployment.live_check_performed %}
        <p>
            <strong>Live Check:</strong> Performed on
            {{ krl_deployment.deployed|length +
               krl_deployment.outdated|length +
               krl_deployment.not_deployed|length +
               krl_deployment.unreachable|length }}
            server(s)
        </p>
        <table>
            <tr><th>Server</th><th>Status</th></tr>
            {% for server in krl_deployment.deployed %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge" style="background-color: #d1fae5; color: #065f46;">
                    ✓ Deployed
                </span></td>
            </tr>
            {% endfor %}
            {% for server in krl_deployment.outdated %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge badge-warning">? Outdated</span></td>
            </tr>
            {% endfor %}
            {% for server in krl_deployment.not_deployed %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge badge-expired">✗ Not Deployed</span></td>
            </tr>
            {% endfor %}
            {% for server in krl_deployment.unreachable %}
            <tr>
                <td>{{ server }}</td>
                <td><span class="badge badge-warning">? Unreachable</span></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p style="color: #666; font-style: italic;">
            No live check performed. Use --inventory to enable live checking.
        </p>
        {% endif %}
    </div>
    {% endif %}

    {% if expiring_soon %}
    <div class="section">
        <h2>⚠️ Certificates Expiring Soon</h2>
        <table>
            <tr><th>Serial</th><th>Identity</th><th>Principals</th><th>Expires</th></tr>
            {% for cert in expiring_soon %}
            <tr>
                <td>{{ cert.serial }}</td>
                <td>{{ cert.identity }}</td>
                <td>{{ cert.principals_display }}</td>
                <td><span class="badge badge-warning">{{ cert.expiration_date }}</span></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    <div class="section">
        <h2>✅ Active Certificates ({{ active|length }})</h2>
        {% if active %}
        <table>
            <tr>
                <th>Serial</th>
                <th>Identity</th>
                <th>Principals</th>
                <th>Signed</th>
                <th>Expires</th>
            </tr>
            {% for cert in active %}
            <tr>
                <td>{{ cert.serial }}</td>
                <td>{{ cert.identity }}</td>
                <td>{{ cert.principals_display }}</td>
                <td>{{ cert.signed_date }}</td>
                <td>{{ cert.expiration_date }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <div class="no-data">No active certificates</div>
        {% endif %}
    </div>

    {% if expired %}
    <div class="section">
        <h2>❌ Expired Certificates ({{ expired|length }})</h2>
        <table>
            <tr><th>Serial</th><th>Identity</th><th>Principals</th><th>Expired</th></tr>
            {% for cert in expired %}
            <tr>
                <td>{{ cert.serial }}</td>
                <td>{{ cert.identity }}</td>
                <td>{{ cert.principals_display }}</td>
                <td><span class="badge badge-expired">{{ cert.expiration_date }}</span></td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if revoked %}
    <div class="section">
        <h2>🚫 Revoked Certificates ({{ revoked|length }})</h2>
        <table>
            <tr>
                <th>Serial</th>
                <th>Identity</th>
                <th>Principals</th>
                <th>Revoked</th>
                <th>Reason</th>
            </tr>
            {% for cert in revoked %}
            <tr>
                <td>{{ cert.serial }}</td>
                <td>{{ cert.identity }}</td>
                <td>{{ cert.principals_display }}</td>
                <td>{{ cert.revoked_date }}</td>
                <td>{{ cert.revocation_reason }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
    <div class="footer"><p>Generated by SSH CA Reporter</p></div>
</body>
</html>"""

    def send_email(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        smtp_host: str = "localhost",
        smtp_port: int = 25,
        smtp_user: str = None,
        smtp_password: str = None,
        smtp_use_tls: bool = False,
        from_addr: str = None,
    ) -> bool:
        """
        Send email report.

        Args:
            recipients: List of email addresses
            subject: Email subject
            html_content: HTML content
            smtp_host: SMTP server
            smtp_port: SMTP port
            smtp_user: SMTP username
            smtp_password: SMTP password
            smtp_use_tls: Use TLS
            from_addr: From address

        Returns:
            True if successful
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr or "sshca-report@localhost"
            msg["To"] = ", ".join(recipients)

            # Attach HTML
            html_part = MIMEText(html_content, "html")
            msg.attach(html_part)

            # Send email
            if smtp_use_tls:
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)

            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)

            server.sendmail(from_addr or "sshca-report@localhost", recipients, msg.as_string())
            server.quit()

            print(f"✅ Report sent to: {', '.join(recipients)}")
            return True

        except Exception as e:
            print(f"❌ Failed to send email: {e}", file=sys.stderr)
            return False


def main():
    """Main entry point."""
    # Get default CA directory from environment or use ~/.sshca
    default_ca_dir = os.path.expanduser(os.environ.get("SSHCA_DIR", "~/.sshca"))

    parser = argparse.ArgumentParser(
        description="SSH CA Certificate Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  SSHCA_DIR    Default CA directory (default: ~/.sshca)

Examples:
  # Use default CA directory
  ssh-ca-report --email admin@example.com

  # Override with environment variable
  SSHCA_DIR=/etc/ssh-ca ssh-ca-report --email admin@example.com

  # Override with command line
  ssh-ca-report --ca-dir /custom/path --email admin@example.com
        """,
    )

    parser.add_argument(
        "--ca-dir",
        default=default_ca_dir,
        help=f"CA directory (default: $SSHCA_DIR or ~/.sshca, currently: {default_ca_dir})",
    )

    parser.add_argument("--output", help="Output HTML file (if not sending email)")

    parser.add_argument("--email", help="Email recipient(s) (comma-separated)")

    parser.add_argument(
        "--subject",
        default="SSH CA Certificate Report",
        help="Email subject (default: SSH CA Certificate Report)",
    )

    parser.add_argument(
        "--inventory", help="Inventory file for live CA deployment checking (optional)"
    )

    parser.add_argument("--smtp-host", default="localhost", help="SMTP server (default: localhost)")

    parser.add_argument("--smtp-port", type=int, default=25, help="SMTP port (default: 25)")

    parser.add_argument("--smtp-user", help="SMTP username")

    parser.add_argument("--smtp-password", help="SMTP password")

    parser.add_argument("--smtp-use-tls", action="store_true", help="Use TLS for SMTP")

    parser.add_argument("--from", dest="from_addr", help="From email address")

    args = parser.parse_args()

    # Create reporter
    reporter = SSHCAReporter(args.ca_dir)

    # Generate report data
    print("Generating report...")
    data = reporter.generate_report_data(args.inventory)

    # Generate HTML
    html = reporter.generate_html_report(data)

    # Output or send
    if args.output:
        # Save to file
        with open(args.output, "w") as f:
            f.write(html)
        print(f"✅ Report saved to: {args.output}")

    if args.email:
        # Send email
        recipients = [r.strip() for r in args.email.split(",")]
        reporter.send_email(
            recipients,
            args.subject,
            html,
            args.smtp_host,
            args.smtp_port,
            args.smtp_user,
            args.smtp_password,
            args.smtp_use_tls,
            args.from_addr,
        )

    if not args.output and not args.email:
        print("Error: Specify --output or --email", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
