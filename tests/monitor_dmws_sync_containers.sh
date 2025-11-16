
#!/usr/bin/env bash

SESSION="DMWS-Sync-Monitor"

COMMAND_0='docker exec -it walytis_identities_tests_device_0 /bin/tail -f /opt/walytis_identities/tests/.walytis_identities.log'
COMMAND_1='docker exec -it walytis_identities_tests_device_1 /bin/tail -f /opt/walytis_identities/tests/.walytis_identities.log'
COMMAND_2='docker exec -it walytis_identities_tests_device_2 /bin/tail -f /opt/walytis_identities/tests/.walytis_identities.log'
COMMAND_3='docker exec -it walytis_identities_tests_device_3 /bin/tail -f /opt/walytis_identities/tests/.walytis_identities.log'
# COMMAND_0='watch echo 0'
# COMMAND_1='watch echo 1'
# COMMAND_2='watch echo 2'
# COMMAND_3='watch echo 3'

tmux new-session -d -s "$SESSION" $COMMAND_0

# Split pane 0 vertically (left/right)
tmux split-window -h $COMMAND_2

# Select left pane to split horizontally (top-left/bottom-left)
tmux select-pane -t 0
tmux split-window -v $COMMAND_3

# Select right pane to split horizontally (top-right/bottom-right)
tmux select-pane -t 1
tmux split-window -v $COMMAND_1

# Optional: apply tiled layout (ensures clean 2×2 grid)
tmux select-layout tiled

tmux attach -t "$SESSION"
