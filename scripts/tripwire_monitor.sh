#!/bin/bash
# Tripwire Monitor - checks for decoy sessions without expected su

source /etc/tripwire/tripwire.conf

mkdir -p "$TRACK_DIR"

log_alert() {
    local level="$1"
    local message="$2"
    logger -p "auth.${level}" -t TRIPWIRE "$message"
}

check_su_occurred() {
    local parent_pid="$1"
    local target_user="$PRIVILEGED_USER"

    # Check if any process owned by target user has this session as ancestor
    for pid in $(pgrep -u "$target_user" 2>/dev/null); do
        # Walk up the process tree
        current_pid=$pid
        while [ "$current_pid" -gt 1 ]; do
            if [ "$current_pid" -eq "$parent_pid" ]; then
                return 0  # Found - su occurred
            fi
            current_pid=$(ps -o ppid= -p "$current_pid" 2>/dev/null | tr -d ' ')
            [ -z "$current_pid" ] && break
        done
    done

    return 1  # Not found
}

while true; do
    sleep 30  # Check every 30 seconds for faster response

    NOW=$(date +%s)

    for TRACK_FILE in "$TRACK_DIR"/*; do
        [ -f "$TRACK_FILE" ] || continue
        [[ "$TRACK_FILE" == *.alerted ]] && continue

        # Read tracking data
        unset user pid rhost tty start
        source "$TRACK_FILE"

        [ -z "$user" ] || [ -z "$pid" ] || [ -z "$start" ] && continue

        ELAPSED=$((NOW - start))

        # Check if session still active
        if ! ps -p "$pid" &>/dev/null; then
            rm -f "$TRACK_FILE" "${TRACK_FILE}.alerted" 2>/dev/null
            continue
        fi

        # Check if user has su'd to expected target
        if check_su_occurred "$pid"; then
            log_alert "info" "LEGITIMATE user=$user completed su to $PRIVILEGED_USER after ${ELAPSED}s"
            rm -f "$TRACK_FILE" "${TRACK_FILE}.alerted" 2>/dev/null
            continue
        fi

        # Alert at timeout
        if [ "$ELAPSED" -ge "$INACTIVITY_TIMEOUT" ]; then
            if [ ! -f "${TRACK_FILE}.alerted" ]; then
                log_alert "alert" "INACTIVE_DECOY user=$user rhost=$rhost tty=$tty elapsed=${ELAPSED}s expected_su=$PRIVILEGED_USER"
                touch "${TRACK_FILE}.alerted"
            fi
        fi
    done
done
