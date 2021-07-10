


import requests
import json


ryu_ip= '127.0.0.1'
ryu_port = '8081'
timer ='3000'
priority= '2'
switches = list()


data = [[ '1', {'IN_PORT':'1','SRC':'1','DST':'2','OUT_PORT':'3'},
               {'IN_PORT':'3','SRC':'2','DST':'1','OUT_PORT':'1'}],
        [ '2', {'IN_PORT':'2','SRC':'1','DST':'2','OUT_PORT':'3'},
               {'IN_PORT':'3','SRC':'2','DST':'1','OUT_PORT':'2'}],
        [ '3', {'IN_PORT':'1','SRC':'1','DST':'2','OUT_PORT':'2'},
               {'IN_PORT':'2','SRC':'2','DST':'1','OUT_PORT':'1'}],
        [ '4', {'IN_PORT':'1','SRC':'1','DST':'2','OUT_PORT':'2'},
               {'IN_PORT':'2','SRC':'2','DST':'1','OUT_PORT':'1'}]               
               ]
               
flow_entry ="""{
    "dpid": %s,
    "table_id": 0,
    "idle_timeout":%s,
    "hard timeout": %s,
    "priority": %s,
    "match" :{
            "in port": "%s",
            "dl_src": "00:00:00:00:00:0%s",
            "dl_dst": "00:00:00:00:00:0%s"
            },
    "actions": [
        {
            "type" : "OUTPUT",
            "port": %s
        }

]
}"""

# Process dataset and upload to Ryu controller
url_post = 'http://{}:{}/stats/flowentry/add'.format(ryu_ip,ryu_port)
   
"""Post Code """
for switch in data:
    switches.append(switch[0])
    dpid = switch[0]
    print('\nUploading flows for OvS sc{}'.format(dpid))
    iter_flows = iter(switch)
    next(iter_flows)
    for flow in iter_flows:
        flow_items=(flow['IN_PORT'],flow['SRC'], flow['DST'], flow['OUT_PORT'])
        print("\nflow_items",flow_items,"\n")
        all_items=(dpid, timer,timer,priority) +flow_items
        print("\nall_items",all_items,"\n")
        this_flow = flow_entry % all_items # Replace all items in tuple for &s
        print("\nthis_flow",this_flow,"\n")
        this_flow_dict = json.loads(this_flow) # Convert str to dict
        # Send URL to Ryu controller
        response = requests.post(url_post, data=this_flow)
        if (response.ok):
            print('In port: %s, SRC: %s DST: %s Out port: %s' % flow_items)
        else:
            print('There is a problem connecting to REST API')
            exit(1)

print('\nALL flows added')

"""Get Code """
# Get the JSON output from the RESTful API confirming flows
for switch in switches:
    url_get = 'http://{}:{}/stats/flow/{}'.format(ryu_ip, ryu_port, switch)
    response = requests.get(url_get)
    response_bytes = response.content
    response_str = response_bytes.decode("utf-8")
    print()
    if (response.ok):
        json_dict = json.loads(response_str)
        print (json_dict)
        print()
    else:
        print('There has been a problem connecting to REST API')
        exit(1)
print('''
You can also check the flows with the following commands:

sudo ovs-ofctl protocols OpenFlow13 dump-flows s1
sudo ovs-ofctl protocols OpenFlow13 dump-flows s2
sudo ovs-ofctl protocols OpenFlow13 dump-flows s3
''') 

# End
exit (0)


"""
page 53

sudo python3 simple

ryu-manager --ofp-tcp-listen-port 6653 --wsapi-port 8081  --verbose app1.py ryu.app.ofctl_rest

 sudo python3 simple_redundant_topo.py




"""
