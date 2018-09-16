#imports
import os
import pandas as pd
num_hops = 30  # default


aliveness_report = "nust.edu.pk_ip_aliveness_report.csv"

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

def findPaths(aliveness_report,num_hops = 30):
    root_directory = os.getcwd()
    if not os.path.exists("tmp"):
        os.makedirs("tmp")
    os.chdir("tmp") 
    print aliveness_report
    print os.getcwd()
    # read the file and store data
    df = pd.read_csv(aliveness_report)
    for index, row in df.iterrows():
        dict_row =  row.to_dict()
        tcp_alive = []
        alive_protocols = protocol_aliveness(dict_row)
        if "tcp" in alive_protocols:
            tcp_alive = alive_tcp_ports(dict_row)
        print tcp_alive
        for protocol in alive_protocols:
            tmp_dir = os.getcwd()
            os.chdir(aliveness_report.split("_")[0])
            command_icmp = "sudo traceroute -I {} > {}_icmp_route.txt".format(row["IP"],row["IP"])
            command_udp_static_port = "sudo traceroute -U {} > {}_udp_static.txt".format(row["IP"],row["IP"])
            command_udp_incrementing_port = "sudo traceroute {} > {}_udp_inc.txt".format(row["IP"],row["IP"])
            if not os.path.exists("paths"):
                os.makedirs("paths")
            os.chdir("paths")
            print "running ICMP scans"
            os.system(command_icmp)
            print "running UDP scans"
            os.system(command_udp_static_port)
            os.system(command_udp_incrementing_port)
            print "running TCP scans"
            for port in tcp_alive:
                print "scanning port {}".format(port)
                command_tcp = "sudo tcptraceroute {} {} > {}_tcp_{}.txt".format(row["IP"],port,port,row["IP"])
                os.system(command_tcp)
                
    os.chdir(root_directory)


    # print "finding paths to the ips"






#findPaths(aliveness_report)