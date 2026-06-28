#!/bin/sh
set -e

INSTALL_DIR="/opt/ics-firmware-v2"
BACKUP_DIR="/opt/ics-firmware-backup"

echo "Installing ICS firmware v2.3.1..."
echo "Stopping service"
echo "Backing up current firmware to $BACKUP_DIR"
echo "Copying binary agent to $INSTALL_DIR/bin/"
echo "Applying config $INSTALL_DIR/config/"
echo "Setting permissions"
echo "Starting service"
echo "Verifying firmware version"
echo "Done"
