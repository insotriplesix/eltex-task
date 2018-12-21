#!/bin/bash

make && make load && sudo mknod ./tufilter c 444 0

#---------------------------------------------------------------

# it`s ok, but there is nuffin' to watch yet

sudo ./user --show

# ok requests, fill the table

sudo ./user -?

sudo ./user -p 1488 -i 192.25.25.254 -t tcp -f enable -r in
sudo ./user -p 1337 -i 66.69.69.99 -t udp -f enable -r out
sudo ./user -p 666 -i 255.255.255.255 -t tcp -f enable -r in

sudo ./user -p 982 -f enable -t udp -r out
sudo ./user -i 1.4.8.8 -t udp -f enable -r out

sudo ./user --port 696 -t tcp -f enable --route in
sudo ./user -p 696 --transport udp -f enable --route out

sudo ./user --ip 212.5.5.5 -t tcp -f enable --route out
sudo ./user -i 224.3.31.1 --transport udp -f enable -r in

sudo ./user --port 3000 -t tcp --show -f enable --route in

# it`s ok too, but the table is already full

sudo ./user --port 5000 -t tcp -f enable --route in

# bad requests

sudo ./user
sudo ./user -t tcp -f disable
sudo ./user --prikol 80085 --ip 1.2.3.4 -f enable
sudo ./user --port 9999999 -f disable
sudo ./user --ip 999.999.999.999.999 -t tcp -f enable
sudo ./user --ip 256.255.254.253 -t tcp -f enable
sudo ./user -i 228.229.230.231 --transport udp -f enablez
sudo ./user -i 4.4.24.94 --transport -f enable
sudo ./user -i 2.2.24.50 --transport udp -f disable -r inn

# disable rules

sudo ./user -s

sudo ./user --ip 212.5.5.5 -t tcp -f disable --route out -s
sudo ./user -i 224.3.31.1 --transport udp -f disable -r in -s

# skip duplicates

sudo ./user -p 1488 -i 192.25.25.254 -t tcp -f enable -r in
sudo ./user -p 1337 -i 66.69.69.99 -t udp -f enable -r out
sudo ./user -p 666 -i 255.255.255.255 -t tcp -f enable -r in

sudo ./user --show

#---------------------------------------------------------------

make unload && make clean && sudo rm tufilter
