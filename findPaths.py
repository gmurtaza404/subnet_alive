# help
"""
    To run this tool independently...
    1. Type python to open python shell
    2. import findPaths
    3. findPaths.findPaths([aliveness_file_name])

    This script traces path to all the ips in the file, it also takes into account the information,
    regarding the open ports. For example, if an IP is responsive on port 80 only, so this scrip will
    probe to that IP using tcptraceroute on port 80. This script pipes out all the reports of the
    the different probes into txt files in /domain_name/paths directory
"""
#dependencies
"""
    To use install pandas, traceroute, and tcptraceroute
    sudo pip install pandas
    sudo apt-get install traceroute
    sudo apt-get install tcptraceroute
"""
#imports
import os
import pandas as pd

def protocol_aliveness(row):
    temp_list = []
    for key in row:
        if key =="IP":
            continue
        else:
            if row[key]:   
                temp_list.append(key.split("_")[0])
    return list(set(temp_list))

def alive_tcp_ports(row):
    temp_list = []
    for key in row:
        if key.split("_")[0] =="tcp" and row[key]:
            temp_list.append(key.split("_")[1])
    return list(set(temp_list))

"""
    @params
        string aliveness_report (File that contains the information which ips are alive and are responsive
                                    on which ports, too see the see).
    @returns
        return path of the folder which contains all the txt files.
"""

def findPaths(aliveness_report):
    root_directory = os.getcwd()
    ret_path = ""
    if not os.path.exists("tmp"):
        os.makedirs("tmp")
    os.chdir("tmp")
    path_to_tmp = os.getcwd() 
    # read the file and store data
    df = pd.read_csv(aliveness_report)
    os.chdir(aliveness_report.split("_")[0])
    path_to_main_folder = os.getcwd()
    for index, row in df.iterrows():
        dict_row =  row.to_dict()
        tcp_alive = []
        alive_protocols = protocol_aliveness(dict_row)
        os.chdir(path_to_main_folder)
        print "Running on IP: {}".format(row["IP"])
        if "tcp" in alive_protocols:
            tcp_alive = alive_tcp_ports(dict_row)
        if not os.path.exists("paths"):
            os.makedirs("paths")
        os.chdir("paths")
        ret_path = os.getcwd()
        command_icmp = "sudo traceroute -I {} > {}_echo_icmp.txt".format(row["IP"],row["IP"])
        command_udp_static_port = "sudo traceroute -U {} > {}_static_udp.txt".format(row["IP"],row["IP"])
        command_udp_incrementing_port = "sudo traceroute {} > {}_inc_udp.txt".format(row["IP"],row["IP"])
        
        print "running ICMP traceroutes"
        os.system(command_icmp)
        print "running UDP traceroutes"
        #os.system(command_udp_static_port)
        #os.system(command_udp_incrementing_port)
        print "running TCP traceroutes..."
        for port in tcp_alive:
            print "on port {}".format(port)
            command_tcp = "sudo tcptraceroute {} {} > {}_tcp_{}.txt".format(row["IP"],port,port,row["IP"])
            os.system(command_tcp)
                
    os.chdir(root_directory)
    return ret_path
