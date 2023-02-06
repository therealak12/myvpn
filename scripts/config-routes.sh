sudo ip r delete default via 192.168.1.1 dev wlo1 proto dhcp metric 600
sudo ip r add default via 10.0.0.2
sudo ip r add 78.109.200.248 via 192.168.1.1
