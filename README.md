

# Service Discovery Helper
### A UDP Broadcast forwarder 
### (c) Chris Holman, 2013

If you operate a network with more than one VLAN or LAN segment, then UDP broadcast discovery wont 
*just work* across your entire network. Enter, Service Discovery Helper (SDH).

Many programs use UDP broadcasts to discover their servers/peers. SDH forwards these UDP broadcasts between 
enable the discovery functionality where it would not usually work.

SDH will listen on the specified network interfaces for UDP broadcasts on certain
ports and copy them out to the remaining network interfaces. It uses a whitelist
for UDP ports that it will forward, so you can be sure that you will not
accidentally forward DHCP or SSDP to every other VLAN. 

The use case that inspired this tool is large LAN parties, where you may have hundreds
(or thousands!) of PCs on one network. Operating this many PCs on one broadcast domain 
introduces a number of issues, and is considered probably not the best practice. 
The normal networking solution to this is to segment the network in to a number of 
VLANs on their own subnet, such that there are a much smaller number of PCs in one 
broadcast domain. But then game server discovery doesn't work!


### What SDH *does* do 

1. Copy/retransmit ethernet frames containing UDP broadcast packets on whitelisted ports between network interfaces

### What SDH **does not** do

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

So far, nothing much. I have tested it on Valve's Source engine, and it works perfectly. It has yet to be used in a production environment. 

### License

See LICENSE for licensing information. 


