# main driver file
"""
    To run this driver script, just type 
        sudo python network_topology.py [name_of_domain]
        for example, if we want the topology of the lums domain, then we can get that by running command,
        sudo python network_topology.py lums.edu.pk
        similarly for NUST
        sudo python network_topology.py nust.edu.pk
"""
#imports
import resolve
import aliveIps
import findPaths
import parseFiles
import argparse

#dependencies
"""
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
"""












def main():
    #argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_name" ,help="domain name you want to scan and make topology of.")
    args = parser.parse_args()

    #actual pipeline
    allocated_subnets = resolve.resolve_domain(args.domain_name)
    
    if allocated_subnets != "failed":
        aliveness_report = aliveIps.check_aliveness(allocated_subnets,True,False,True)
        path = findPaths.findPaths(aliveness_report)
        parseFiles.make_graph(path)
        print "Done..."
    else:
        print "Invalid Domain name"
        exit(1)
main()