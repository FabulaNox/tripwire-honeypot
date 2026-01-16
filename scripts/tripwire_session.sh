#!/bin/bash
# Tripwire Session Tracker - called by PAM on session open/close

source /etc/tripwire/tripwire.conf

mkdir -p "$TRACK_DIR"
chmod 700 "$TRACK_DIR"

case "$PAM_TYPE" in
    open_session)
        if echo "$DECOY_USERS" | grep -qw "$PAM_USER"; then
            TIMESTAMP=$(date +%s)
            TRACK_FILE="$TRACK_DIR/${PAM_USER}_$$_${TIMESTAMP}"

            cat > "$TRACK_FILE" << EOF
user=$PAM_USER
pid=$$
rhost=$PAM_RHOST
tty=$PAM_TTY
start=$TIMESTAMP
EOF
            logger -p auth.notice -t TRIPWIRE "SESSION_START user=$PAM_USER rhost=$PAM_RHOST tty=$PAM_TTY pid=$$"
        fi
        ;;
    close_session)
        if echo "$DECOY_USERS" | grep -qw "$PAM_USER"; then
            logger -p auth.notice -t TRIPWIRE "SESSION_END user=$PAM_USER rhost=$PAM_RHOST tty=$PAM_TTY pid=$$"
        fi
        rm -f "$TRACK_DIR/${PAM_USER}_$$_"* 2>/dev/null
        rm -f "$TRACK_DIR/${PAM_USER}_$$_"*.alerted 2>/dev/null
        ;;
esac

exit 0
