# subnet_alive
Description:
    This tool takes in a domain name and generates a rough topology of paths to that domain.
    
Dependencies:
    
    1. resolve.py
        sudo pip install ipwhois
            dependencies ->sudo pip install dnspython
                        ->sudo pip install ipaddr
    
    2. aliveIps.py
        None
    
    3. findPaths.py
        sudo pip install pandas
        sudo apt-get install traceroute
        sudo apt-get install tcptraceroute
    
    4. parseFiles.py
        sudo pip install graphviz

    5. network_topology.py
        sudo pip install argparse

How to run:
    To run this driver script, just type 
        sudo python network_topology.py [name_of_domain]
        for example, if we want the topology of the lums domain, then we can get that by running command,
        sudo python network_topology.py lums.edu.pk
        similarly for NUST
        sudo python network_topology.py nust.edu.pk
