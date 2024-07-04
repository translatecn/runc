source /etc/profile


cp -rf /Users/acejilam/Desktop/runc/runc /usr/bin/runc

pkill -9 containerd
pkill -9 dlv
pkill -9 crictl

rm -rf /var/lib/containers/*
rm -rf /var/lib/containerd/*
rm -rf /run/containerd/*
rm -rf /etc/kubernetes/*
rm -rf /etc/containers/*
rm -rf /etc/cni/net.d/*
rm -rf /var/lib/cni/*
rm -rf /etc/cdi/*     # 静态配置
rm -rf /var/run/cdi/* # 动态配置

#/opt/cni/bin

mkdir -p /etc/cni/net.d
mkdir -p /run/flannel

cat > /run/flannel/subnet.env << EOF
FLANNEL_NETWORK=100.64.0.0/16
FLANNEL_SUBNET=100.64.0.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=true
EOF

cat > /etc/cni/net.d/10-flannel.conflist << EOF
{
  "cniVersion": "0.3.1",
  "name": "cbr0",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
        "hairpinMode": true,
        "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}
EOF



/Users/acejilam/Desktop/containerd/bin/containerd -c /Users/acejilam/Desktop/containerd/cmd/containerd/config.toml &

md5sum /Users/acejilam/Desktop/runc/runc
md5sum /usr/bin/runc
sleep 4

/Users/acejilam/Desktop/containerd/bin/crictl runp --runtime=runc /Users/acejilam/Desktop/containerd/examples/sandbox-config.yaml
