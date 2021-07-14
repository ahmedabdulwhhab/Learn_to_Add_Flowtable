"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.


sudo mn --custom ring_topo.py --topo mytopo  --controller remote,ip=192.168.0.100 --switch ovsk,protocols=OpenFlow13 --mac --ipbase=10.1.1.0/24



"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def build( self ):
        "Create custom topo."

        # Add hosts and switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )
        s5 = self.addSwitch( 's5' )

        # Add links
        self.addLink( h1, s1 )
        self.addLink( s1,s2 )
        self.addLink( s2, s5 )
        self.addLink( s5, h2 )
        self.addLink( s5, s4 )
        self.addLink( s4, s3 )
        self.addLink( s3, s1 )

        #self.addLink( h2, s2 )
        #self.addLink( h2, s2 )
        #self.addLink( s1, s2 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
        
