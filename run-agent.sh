#!/bin/bash

# 1. Capture the arguments
USER_ARG="$1"
USER_FILENAME="$2"  # New argument for the filename
CONT_USER_FILENAME=$(basename "$2")  # New argument for the filename
AGENT_FOLDER="$3"

# Validate that all 3 required script parameters are present
if [ -z "$USER_ARG" ] || [ -z "$USER_FILENAME" ] || [ -z "$AGENT_FOLDER" ]; then
    echo "Error: Missing required arguments."
    echo "Usage: $0 <agent_binary_checksum> <secret_filename> <agent_config_subfolder> [arguments_for_container...]"
    echo ""
    echo "Example:"
    echo "  $0 0ccX4ffa production.yaml goose_agent --some-container-flag"
    exit 1
fi


# 2. Determine Paths
AGENT_PATH=$(pwd)
AGENT_CONFIG="/root/.config"
LOCAL_FUSE="$AGENT_PATH/fuse_mnt"
LOCAL_SECRET="$AGENT_PATH/config"
LOCAL_WORKSPACE="$AGENT_PATH/workspace"

CONT_CONFIG="$AGENT_CONFIG/$AGENT_FOLDER"
CONT_WORKSPACE="/workspace"

echo "$LOCAL_SECRET -> $CONT_CONFIG"
echo "$LOCAL_WORKSPACE -> $CONT_WORKSPACE"

# 3. Validation
for dir in "$LOCAL_SECRET" "$LOCAL_WORKSPACE"; do
    if [ ! -d "$dir" ]; then
        echo -e "\e[31mError: Directory $dir not found. Is this really a Goose agent workspace?\033[0m"
        exit 1
    fi
done

mkdir -p "$LOCAL_FUSE"

# 4. Find the EXACT Python executable
PYTHON_EXEC=$(command -v python || command -v python3)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

echo "Verifying dependencies..."
$PYTHON_EXEC -m ensurepip || { echo -e "\e[31mCould not ensure python & pip are available. Maybe you need to run in a uv venv?\033[0m"; exit 1; }
$PYTHON_EXEC -m pip install -q fusepy || { echo -e "\e[31mPip install failed\033[0m"; exit 1; }

# 5. Start Python Background Process with Pipe Monitor
echo "Starting Python FUSE, sudo privileges required..."
sudo -v

# Create a pipe
PIPE_FILE=$(mktemp -u)
mkfifo "$PIPE_FILE"

# Launch the monitored sudo process
# Passed $USER_FILENAME into the FUSE script arguments (-f)
sudo bash -c "
  exec 3<\"$PIPE_FILE\"
  
  echo \"starting FUSE.\"
  $PYTHON_EXEC -I \"$SCRIPT_DIR/config_fuse.py\" -s \"$USER_ARG\" \"$LOCAL_FUSE\" -f \"$USER_FILENAME\" &
  
  CHILD_PID=\$!
  
  read <&3
  echo \"FUSE process detected that the container process died, shutting down.\"
  kill \$CHILD_PID 2>/dev/null
" &
PYTHON_MONITOR_PID=$!

exec 3>"$PIPE_FILE"
rm "$PIPE_FILE" 

# 6. Wait for file
LOCAL_FUSE_FILE="$LOCAL_FUSE/$CONT_USER_FILENAME" # mount as this in host
CONT_FUSE_FILE="/fuse/$CONT_USER_FILENAME" # mount as fuse/... in container
CONT_AGENT_FILE="$LOCAL_SECRET/$CONT_USER_FILENAME" # symlink as this in container

echo -n "Waiting for $LOCAL_FUSE_FILE to be generated..."
while [ ! -f "$LOCAL_FUSE_FILE" ]; do
    echo -n "."
    sleep 1
    if ! kill -0 $PYTHON_MONITOR_PID 2>/dev/null; then
        echo -e "\nError: Python monitor process died."
        exit 1
    fi
done
echo -e "\nFile found!"

# 7. Create Symlink
sudo ln -sf "$CONT_FUSE_FILE" "$CONT_AGENT_FILE" || { echo -e "\e[31mSymlink failed\033[0m"; exit 1; } 
echo "Symlink created: $CONT_AGENT_FILE -> $CONT_FUSE_FILE"

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    exec 3>&-
    
    [ -L "$CONT_AGENT_FILE" ] && rm "$CONT_AGENT_FILE"
}

trap cleanup SIGINT SIGTERM EXIT

# 8. Run Docker
shift 3 # drop all shell arguments (the hash, filename, ...)

echo "Setting up rootless docker..."

# 1. Automatically find the container binary (docker or podman)
if command -v podman >/dev/null 2>&1; then
    CONTAINER_BIN=$(command -v podman)
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_BIN=$(command -v docker)
else
    echo -e "\e[31mERROR: Neither docker nor podman was found in your PATH.\033[0m"
    exit 1
fi

# 2. If it's Docker, set up the rootless environment variables
if [[ "$CONTAINER_BIN" == *"docker"* ]]; then
    echo "Setting up rootless docker..."
    export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
    
    # Start the user-level docker service if it's not running
    systemctl --user start docker.service 2>/dev/null || true

    CURRENT_ENDPOINT=$("$CONTAINER_BIN" context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || echo "")
    EXPECTED_ENDPOINT="unix:///run/user/$(id -u)/docker.sock"

    if [ "$CURRENT_ENDPOINT" = "$EXPECTED_ENDPOINT" ]; then
        echo "Check passed: Verified connection to Rootless socket."
    else
        echo "Warning: Rootless socket check bypassed or mismatched. Attempting run anyway..."
    fi
else
    echo "Using Podman environment..."
fi


NAME=$(basename "$PWD")_$(date +%Y_%m_%d-%H_%M_%S)
echo "Launching '$NAME' Docker session..."


"$CONTAINER_BIN" run -it \
  --rm \
  --name $NAME \
  -m 224G --cpus="90" \
  -v "$LOCAL_SECRET:$CONT_CONFIG:slave" \
  -v "$LOCAL_WORKSPACE:$CONT_WORKSPACE:slave" \
  -v "./plans/shared:$CONT_WORKSPACE/plans" \
  -v "$LOCAL_FUSE:/fuse:ro" \
  --workdir "$CONT_WORKSPACE" \
  agentbox "$@"