#!/usr/bin/python
#python 2
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node , Controller, RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.util import irange
from mininet.link import TCLink


#sudo python python_topo00.py  
#https://192.168.0.105:8443/sdn/ui/app/index#oftopology
c0=RemoteController( 'c0', ip='192.168.0.105' )

class NetworkTopo( Topo ):
    "A simple topology of a double-star access/dist/core."

    def build( self ):

        h1 =  self.addHost( 'h1',  ip='10.10.2.1/24', defaultRoute='via 10.10.2.254' )
        h2 =  self.addHost( 'h2',  ip='10.10.2.2/24', defaultRoute='via 10.10.2.254' )
        h3 =  self.addHost( 'h3',  ip='10.10.2.3/24', defaultRoute='via 10.10.2.254' )
        h4 =  self.addHost( 'h4',  ip='10.10.2.4/24', defaultRoute='via 10.10.2.254' )
        h5 =  self.addHost( 'h5',  ip='10.10.2.5/24', defaultRoute='via 10.10.2.254' )
        h6 =  self.addHost( 'h6',  ip='10.10.2.6/24', defaultRoute='via 10.10.2.254' )
        
        h7 =  self.addHost( 'h7',  ip='10.10.2.7/24', defaultRoute='via 10.10.2.254' )
        h8 =  self.addHost( 'h8',  ip='10.10.2.8/24', defaultRoute='via 10.10.2.254' )
        h9 =  self.addHost( 'h9',  ip='10.10.2.9/24', defaultRoute='via 10.10.2.254' )
        h10 = self.addHost( 'h10', ip='10.10.2.10/24', defaultRoute='via 10.10.2.254' )        
        h11 = self.addHost( 'h11', ip='10.10.2.11/24', defaultRoute='via 10.10.2.254' )   
        h12 = self.addHost( 'h12', ip='10.10.2.12/24', defaultRoute='via 10.10.2.254' )           
        h13 = self.addHost( 'h13', ip='10.10.2.13/24', defaultRoute='via 10.10.2.254' )   
        h14 = self.addHost( 'h14', ip='10.10.2.14/24', defaultRoute='via 10.10.2.254' )   
        h15 = self.addHost( 'h15', ip='10.10.2.15/24', defaultRoute='via 10.10.2.254' )   
        h16 = self.addHost( 'h16', ip='10.10.2.16/24', defaultRoute='via 10.10.2.254' )           

        
        sc1 = self.addSwitch( 'sc1', dpid='0000000000000001',protocols='OpenFlow13' )
        sc2 = self.addSwitch( 'sc2', dpid='0000000000000002',protocols='OpenFlow13' )
        sc3 = self.addSwitch( 'sc3', dpid='0000000000000003',protocols='OpenFlow13' )
        sc4 = self.addSwitch( 'sc4', dpid='0000000000000004',protocols='OpenFlow13' )
 
        
        sa1 = self.addSwitch( 'sa1', dpid='0000000000000005',protocols='OpenFlow13' )
        sa2 = self.addSwitch( 'sa2', dpid='0000000000000006',protocols='OpenFlow13' )
        sa3 = self.addSwitch( 'sa3', dpid='0000000000000007',protocols='OpenFlow13' )
        sa4 = self.addSwitch( 'sa4', dpid='0000000000000008',protocols='OpenFlow13' )
        sa5 = self.addSwitch( 'sa5', dpid='0000000000000009',protocols='OpenFlow13' )
        sa6 = self.addSwitch( 'sa6', dpid='0000000000000010',protocols='OpenFlow13' )
        sa7 = self.addSwitch( 'sa7', dpid='0000000000000011',protocols='OpenFlow13' )
        sa8 = self.addSwitch( 'sa8', dpid='0000000000000012',protocols='OpenFlow13' )        
        
        se1 = self.addSwitch( 'se1', dpid='0000000000000013',protocols='OpenFlow13' )
        se2 = self.addSwitch( 'se2', dpid='0000000000000014',protocols='OpenFlow13' )
        se3 = self.addSwitch( 'se3', dpid='0000000000000015',protocols='OpenFlow13' )
        se4 = self.addSwitch( 'se4', dpid='0000000000000016',protocols='OpenFlow13' )
        se5 = self.addSwitch( 'se5', dpid='0000000000000017',protocols='OpenFlow13' )
        se6 = self.addSwitch( 'se6', dpid='0000000000000018',protocols='OpenFlow13' )
        se7 = self.addSwitch( 'se7', dpid='0000000000000019',protocols='OpenFlow13' )
        se8 = self.addSwitch( 'se8', dpid='0000000000000020',protocols='OpenFlow13' ) 

        #core
        self.addLink ( sc1, sa1 )
        self.addLink ( sc1, sa4 )        
        self.addLink ( sc1, sa6 )                
        self.addLink ( sc1, sa7 )        

        self.addLink ( sc2, sa1 )
        self.addLink ( sc2, sa3 )        
        self.addLink ( sc2, sa6 )                
        self.addLink ( sc2, sa8 )        
        
        self.addLink ( sc3, sa2 )
        self.addLink ( sc3, sa3 )        
        self.addLink ( sc3, sa5 )                
        self.addLink ( sc3, sa8 )        

        self.addLink ( sc4, sa2 )
        self.addLink ( sc4, sa4 )        
        self.addLink ( sc4, sa5 )                
        self.addLink ( sc4, sa7 )                

        #Aggregretise
        self.addLink ( sa1, se1 )
        self.addLink ( sa1, se2 )
        self.addLink ( sa2, se1 )
        self.addLink ( sa2, se2 )

        self.addLink ( sa3, se3 )
        self.addLink ( sa3, se4 )
        self.addLink ( sa4, se3 )
        self.addLink ( sa4, se4 )

        self.addLink ( sa5, se5 )
        self.addLink ( sa5, se6 )
        self.addLink ( sa6, se5 )
        self.addLink ( sa6, se6 )

        self.addLink ( sa7, se7 )
        self.addLink ( sa7, se8 )
        self.addLink ( sa8, se7 )
        self.addLink ( sa8, se8 )
        #acccess
        self.addLink( se1, h1 )
        self.addLink( se1, h2 )
        self.addLink( se2, h3 )
        self.addLink( se2, h4 )
        self.addLink( se3, h5 )
        self.addLink( se3, h6 )
        self.addLink( se4, h7 )
        self.addLink( se4, h8 )
        self.addLink( se5, h9 )
        self.addLink( se5, h10 )        
        self.addLink( se6, h11 )        
        self.addLink( se6, h12 )        
        self.addLink( se7, h13 )  
        self.addLink( se7, h14 )        
        self.addLink( se8, h15 )        
        self.addLink( se8, h16 )         

def run():
    topo = NetworkTopo()
    net = Mininet( topo=topo, controller=c0 )
    net.start()

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
