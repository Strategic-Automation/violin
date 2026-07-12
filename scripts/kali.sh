#!/usr/bin/env bash
# Kali container exec helper for the Violin Hermes profile.
#
# Usage:  kali <command> [args...]
#   Runs <command> inside the kali-pentest Docker container.
#   All args are passed through verbatim.
#
# Examples:
#   kali nmap -sV -p 80,443 target.com
#   kali ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
#   kali python3 -c "print('hello from kali')"
#   kali bash -c "which nmap && nmap --version"
#
# The container mounts /engagements -> ./engagements/ in the Violin repo,
# so evidence and output files written to /engagements/ are accessible
# from the host at C:\Users\Hello\repos\violin\engagements\.
#
# If the container isn't running, starts it automatically.

CONTAINER_NAME="kali-pentest"

# Ensure container is running
docker start "$CONTAINER_NAME" > /dev/null 2>&1 || true

# Execute the command inside the container
if [ $# -eq 0 ]; then
  echo "Usage: kali <command> [args...]"
  echo "Runs a command inside the kali-pentest Docker container."
  echo ""
  echo "Examples:"
  echo "  kali nmap -sV target.com"
  echo "  kali ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt"
  echo "  kali bash                  # interactive shell (use pty mode)"
  exit 1
fi

docker exec -i "$CONTAINER_NAME" "$@"