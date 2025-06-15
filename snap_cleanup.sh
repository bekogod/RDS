#!/bin/bash

# Ensure the script is run with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Use: sudo $0"
    exit 1
fi

# Remove all disabled Snap versions
snap list --all | awk '/disabled/{print $1, $3}' | while read -r snap_name snap_revision; do
    echo "Removing disabled version: $snap_name (rev: $snap_revision)"
    snap remove "$snap_name" --revision="$snap_revision"
done

# Clear Snap cache
echo "Clearing Snap cache..."
rm -rf /var/lib/snapd/cache/*

echo "Cleanup complete!"
