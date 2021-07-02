#!/usr/bin/python
#python 2 on mininet
#python3 on ubuntu 20.04
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node , Controller, RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import irange
from mininet.link import TCLink


#sudo python3 python_topo00.py  
#https://192.168.0.105:8443/sdn/ui/app/index#oftopology
#ryu-manager --ofp-tcp-listen-port 6653 --wsapi-port 8081 ryu.app.simple_switch_stp_13  ryu.app.ofctl_rest

c0=RemoteController( 'c0', ip='192.168.0.105' )

class NetworkTopo( Topo ):
    "A simple topology of a double-star access/dist/core."

    def build( self ):

        h1 =  self.addHost( 'h1',  ip='10.10.2.1/24' ,mac='00:00:00:00:00:01',defaultRoute='via 10.10.2.254' )
        h2 =  self.addHost( 'h2',  ip='10.10.2.2/24', mac='00:00:00:00:00:02',defaultRoute='via 10.10.2.254' )
 

        
        sc1 = self.addSwitch( 'sc1', dpid='0000000000000001',protocols='OpenFlow13' )
        sc2 = self.addSwitch( 'sc2', dpid='0000000000000002',protocols='OpenFlow13' )
        sc3 = self.addSwitch( 'sc3', dpid='0000000000000003',protocols='OpenFlow13' )
        sc4 = self.addSwitch( 'sc4', dpid='0000000000000004',protocols='OpenFlow13' )

        self.addLink( sc1, h1 )
        self.addLink( sc1, sc4 )
        self.addLink( sc4, sc2 )
        self.addLink( sc1, sc3 )
        self.addLink( sc2, sc3 )
        self.addLink( sc2, h2 )

def run():
    topo = NetworkTopo()
    net = Mininet( topo=topo, controller=c0 )
    net.start()

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
