#!/bin/bash

set -e
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
trap 'echo "\"${last_command}\" returned exit code $?." >&2' EXIT

if [ "$#" -ne 3 ]; then
    echo "Usage: ./bootstrap_node.sh <key_name> <github_repo_url> <github_repo_name>"
    exit 1
fi

KEY_NAME="$1"
REPO_URL="$2"
REPO_NAME="$3"
FUNC="install"

LIMITS="/etc/security/limits.conf"
[ ! -f "$LIMITS".bak ] && sudo cp "$LIMITS" "$LIMITS".bak

printf "* soft     nproc          65535 \n\
* hard     nproc          65535 \n\
* soft     nofile         65535 \n\
* hard     nofile         65535 \n\
root soft     nproc          65535 \n\
root hard     nproc          65535 \n\
root soft     nofile         65535 \n\
root hard     nofile         65535\n" | sudo tee "$LIMITS" >/dev/null

sudo sysctl -w fs.nr_open=65535
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65535 33554432"

grep -qxF "ulimit -n 65535" /home/ubuntu/.bashrc || echo "ulimit -n 65535" >> /home/ubuntu/.bashrc
grep -qxF "ulimit -n 65535" /home/ubuntu/.profile || echo "ulimit -n 65535" >> /home/ubuntu/.profile

mkdir -p /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
chmod 600 /home/ubuntu/"$KEY_NAME"
ssh-keygen -y -f /home/ubuntu/"$KEY_NAME" > /home/ubuntu/"$KEY_NAME".pub
mv /home/ubuntu/"$KEY_NAME"* /home/ubuntu/.ssh
printf "Host github.com\n  HostName github.com\n  IdentityFile ~/.ssh/%s\n  StrictHostKeyChecking no\n" "$KEY_NAME" > /home/ubuntu/.ssh/config

eval "$(ssh-agent)"
ssh-add /home/ubuntu/.ssh/"$KEY_NAME"

sudo apt-get update
sudo apt-get -y upgrade
sudo apt-get -y autoremove
sudo apt-get -y install build-essential cmake clang curl pkg-config libssl-dev

if ! command -v cargo >/dev/null 2>&1; then
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME"/.cargo/env
rustup default stable

cd /home/ubuntu
if [ -L /home/ubuntu/node ]; then unlink /home/ubuntu/node; fi
if [ -L /home/ubuntu/client ]; then unlink /home/ubuntu/client; fi

if [ ! -d "$REPO_NAME" ]; then
    git init
    GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no" git clone "$REPO_URL" "$REPO_NAME"
fi

kill "$SSH_AGENT_PID"
echo "$FUNC complete"
