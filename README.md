

# Service Discovery Helper
##### A UDP Broadcast forwarder 
##### (c) Chris Holman, 2013

If you operate a network with more than one VLAN or LAN segment, then UDP broadcast discovery won't 
*just work* across your entire network. Enter, Service Discovery Helper (SDH).

Many programs use UDP broadcasts to discover their servers/peers. SDH forwards these UDP broadcasts between 
networks, enabling discovery functionality where it would not usually work.

SDH will listen on the specified network interfaces for UDP broadcasts on specified
ports and retransmit the packets on remaining network interfaces. It uses a whitelist
for UDP ports that it will forward, so you can be sure that you will not
accidentally forward DHCP or SSDP to every other VLAN. 

The use case that inspired this tool is large LAN parties, where you may have hundreds
(or thousands!) of PCs on one network. Operating this many PCs on one broadcast domain 
introduces a number of issues, and is considered probably not the best practice. 
The normal solution to this is to segment the network in to a number of 
VLANs on their own subnet, such that there are a much smaller number of PCs in one 
broadcast domain. But then game server discovery doesn't work!

See GAMES.md for a list of tested games. 

### Requirements

* Linux (or maybe BSD or other \*nix environment)
* gcc or similar
* libpcap and libpcap-dev
* Root privilges
* 2 or more local network interfaces

### Usage

Trunk all of your VLANs to a PC somewhere. (Consult switch documentation)

````
 sudo modprobe 8021q
 sudo ip link add eth0 name eth0.2 type vlan id 2
 # Repeat for each VLAN you have
 # Edit the configuration in sdh-proxy.c (command line config coming soon)
 gcc -g -std=gnu99 -o sdh-proxy sdh-proxy.c -lpcap -lpthread
 sudo ./sdh-proxy 
````

Only **one** instance of SDH should run on each VLAN. If more than one instance is run on the same PC, broadcasts will be retransmitted *n* times. If more than one copy is run on more than one PC, and there are shared VLANs, a broadcast loop and flood **will** happen. 

### Advanced usage

If you do not want to trunk every VLAN to one point on your network, you may
create a bridging VLAN and run multiple instances of SDH. Consider the bridging
VLAN is 100, and the user networks are VLANs 101, 102, 103 and 104. Run two
instances of SDH, one connected to VLANs 100, 101 and 102, and the second 
instance connected to VLANs 100, 103 and 104. Packets broadcast on to the bridging VLAN 
will be rebroadcast again by other instances of SDH. 

### What SDH *does* do 

1. Copy/retransmit ethernet frames containing UDP broadcast packets on whitelisted ports between network interfaces

### What SDH *does not* do

1. Routing. This is not a router. Your non-UDP-broadcast IP traffic will still need a normal router to move between LAN segments. 
2. Ethernet bridging. I guess technically it could be considered an ethernet bridge, but only one that 
forwards very incredibly selectively. 
3. Intelligent retransmission decisions. A malicious user could flood your network with targetted traffic. A future feature could be a rate limiter to avoid flooding a gigabit of traffic across the network. 
4. Source verification. Neither source IP or MAC address are verified. A future feature could be to ensure that the source IP address is within the subnet of the interface it was detected on, but this would prevent multi-hop broadcasts. 

The most important bit out of that is: this tool does not carry your game/application traffic. 
Broadcasts are (usually) only used for network announcement and discovery. Your game client 
will send a discovery broadcast packet (ie, host to everyone), which SDH will retransmit. The game server will reply with a 
unicast (ie, host to host). Unicast is not broadcast, and will not be retransmitted by SDH. The unicast packets will go via the path they would have if SDH was not running. 

### What problems might SDH not fix?

Your program might have a serious case of the bad programmer, and cannot deal with "LAN" clients being on different subnets.


### What has this been used for?

So far, nothing much. I have tested it with
 Valve's Source engine, and it works perfectly. It has yet to be used in a production environment. 

### To do list

* Detect whether the broadcast is going to 255.255.255.255 or to the last 
address in the subnet (eg, 10.0.0.255). If the latter, rewrite the address 
for the new subnet. Current implementation leaves address as is. Means it
only works if it gets sent to 255.255.255.255. Making this change would 
require either detection or configuration of what IP range each interface
used.
* Command line configuration
* Option to just use all interfaces on the PC
* Not segfaulting if not run with libpcap capture permissions (eg, root)

Ideas for someone who might find them useful to implement:
* Rate limit (per IP/MAC and globally)
* Verify sender by ARP before retransmitting a frame
* Detect loops by watching for duplicate frames from the same source (this may be problematic, as some applications generate identical frames every time)


### License

Published under the MIT license. See LICENSE for licensing information. Please email me if you use this, I'd love to know <3


