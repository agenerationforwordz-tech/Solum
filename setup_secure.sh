#!/bin/bash
# =============================================================================
# SOLUM SECURITY HARDENING — setup_secure.sh
# =============================================================================
# Option 1: File-level access control via dedicated system user
#
# WHY: Without this, anyone with SSH/filesystem access can bypass all API
# guardrails (admin keys, rate limits, audit trails) by editing the SQLite
# file directly. This script creates a dedicated 'solum' system user and
# restricts DB access to only the Solum process.
#
# WHAT IT DOES:
#   1. Creates a 'solum' system user (no login, no home dir)
#   2. Changes ownership of data files (DB, vault) to solum:solum
#   3. Sets permissions so only the solum user can read/write the DB
#   4. Code files stay readable by everyone (youruser can still edit code)
#   5. Updates the systemd service to run as the solum user
#
# AFTER RUNNING: Direct DB access via SSH is blocked. All access goes
# through the API with proper auth and rate limiting. Admin operations
# require the admin key via the API — no shortcuts.
#
# TO UNDO: sudo chown -R youruser:youruser $DATA_DIR && update systemd User=youruser
# =============================================================================

set -e

# --- Configuration (matches solum.service env vars) ---
SOLUM_USER="solum"
SOLUM_CODE_DIR="/opt/solum"
SOLUM_DATA_DIR="/opt/solum/data"
SOLUM_VAULT_DIR="/opt/solum/data/vault"
SOLUM_LOG_DIR="/opt/solum/logs"
SOLUM_SERVICE="/etc/systemd/system/solum.service"

echo "=== Solum Security Hardening ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Run with sudo — this script needs root to create users and set permissions."
    exit 1
fi

# --- Step 1: Create dedicated system user ---
if id "$SOLUM_USER" &>/dev/null; then
    echo "[OK] User '$SOLUM_USER' already exists"
else
    echo "[+] Creating system user '$SOLUM_USER' (no login, no home dir)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SOLUM_USER"
    echo "[OK] User '$SOLUM_USER' created"
fi

# --- Step 2: Set data directory ownership ---
echo "[+] Setting ownership on data directory: $SOLUM_DATA_DIR"
chown -R "$SOLUM_USER:$SOLUM_USER" "$SOLUM_DATA_DIR"
# DB and vault: owner read/write only. No group, no other.
chmod 700 "$SOLUM_DATA_DIR"
find "$SOLUM_DATA_DIR" -type f -exec chmod 600 {} \;
find "$SOLUM_DATA_DIR" -type d -exec chmod 700 {} \;
echo "[OK] Data directory locked to '$SOLUM_USER' only"

# --- Step 3: Log directory ---
echo "[+] Setting ownership on log directory: $SOLUM_LOG_DIR"
mkdir -p "$SOLUM_LOG_DIR"
chown -R "$SOLUM_USER:$SOLUM_USER" "$SOLUM_LOG_DIR"
chmod 700 "$SOLUM_LOG_DIR"
echo "[OK] Log directory locked"

# --- Step 4: Code stays readable (youruser can edit, solum can execute) ---
echo "[+] Ensuring code directory is readable by '$SOLUM_USER'..."
# Code stays owned by youruser, but world-readable so solum user can execute
chmod -R o+rX "$SOLUM_CODE_DIR"
# Venv needs to be executable by solum
chmod -R o+rX "$SOLUM_CODE_DIR/venv"
echo "[OK] Code directory readable by all, writable by youruser only"

# --- Step 5: Update systemd service ---
echo "[+] Updating systemd service to run as '$SOLUM_USER'..."
if grep -q "User=youruser" "$SOLUM_SERVICE"; then
    sed -i "s/User=youruser/User=$SOLUM_USER/" "$SOLUM_SERVICE"
    echo "[OK] Service updated: User=$SOLUM_USER"
else
    echo "[SKIP] Service already uses User=$SOLUM_USER (or different user)"
fi

# Reload systemd
systemctl daemon-reload

echo ""
echo "=== Hardening Complete ==="
echo ""
echo "What changed:"
echo "  - DB at $SOLUM_DATA_DIR/brain.db is now owned by '$SOLUM_USER'"
echo "  - Only the Solum process can read/write the database"
echo "  - SSH users (including youruser) CANNOT directly access the DB"
echo "  - All access must go through the Solum API with proper auth"
echo "  - Admin operations require the admin key (no filesystem bypass)"
echo ""
echo "To activate: sudo systemctl restart solum"
echo "To undo:     sudo chown -R youruser:youruser $SOLUM_DATA_DIR && sudo sed -i 's/User=solum/User=youruser/' $SOLUM_SERVICE && sudo systemctl daemon-reload"
echo ""
echo "⚠️  Direct DB access is now BLOCKED. Use the API."
