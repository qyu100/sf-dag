#!/bin/bash

set -e
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
trap 'echo "\"${last_command}\" returned exit code $?." >&2' EXIT

if [ "$#" -ne 3 ]; then
    echo "Usage: ./update_node.sh <key_name> <github_repo_name> <repo_branch_name>"
    exit 1
fi

KEY_NAME="$1"
REPO_NAME="$2"
BRANCH_NAME="$3"
FUNC="update"

eval "$(ssh-agent)"
ssh-add /home/ubuntu/.ssh/"$KEY_NAME"

cd /home/ubuntu/"$REPO_NAME"
git fetch -f origin "$BRANCH_NAME"
git checkout -B "$BRANCH_NAME" FETCH_HEAD

source "$HOME"/.cargo/env
cd /home/ubuntu/"$REPO_NAME"/node
cargo build --quiet --release --features benchmark

cd /home/ubuntu/"$REPO_NAME"/benchmark
rm -f node
rm -f client
ln -s ../target/release/node .
ln -s ../target/release/client .

kill "$SSH_AGENT_PID"
echo "$FUNC complete"
