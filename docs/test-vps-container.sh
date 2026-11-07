#!/bin/sh
docker rm -f vps1 >/dev/null 2>&1; docker run -d --name vps1 --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock rxvpn-test-noble:base /sbin/init >/dev/null; sleep 5
docker exec vps1 sh -c 'apt-get update -q >/dev/null 2>&1; apt-get install -y -q openssl >/dev/null 2>&1; mkdir -p /opt/mask && cd /opt/mask && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3 -subj /CN=www.microsoft.com -keyout k.pem -out c.pem 2>/dev/null
printf "[Service]\nExecStart=/usr/bin/openssl s_server -quiet -accept 443 -cert /opt/mask/c.pem -key /opt/mask/k.pem -tls1_3 -alpn h2 -www\nRestart=always\n[Install]\nWantedBy=multi-user.target\n" > /etc/systemd/system/mask.service
systemctl daemon-reload; systemctl enable --now mask >/dev/null 2>&1; echo "127.0.0.1 www.microsoft.com www.apple.com" >> /etc/hosts'
