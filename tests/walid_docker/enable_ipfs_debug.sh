
echo '[Unit]
Description=InterPlanetary FileSystem - the infrastructure of a P2P internet
Wants=ipfs-init.service
Restart=always

[Service]
Environment="IPFS_PATH=/root/.ipfs"
Environment="GOLOG_LOG_LEVEL=debug"
ExecStart=/usr/local/bin/ipfs daemon --enable-pubsub-experiment

[Install]
WantedBy=multi-user.target
' | tee /etc/systemd/system/ipfs.service
