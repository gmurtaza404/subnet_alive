#imports
import argparse
import os
import csv

#globals
tcp_ports = {20:"FTP--Data",21:"FTP--Control",22:"SSH", 53:"DNS", 80:"HTTP", 118:"SQL--Service",443:"HTTPS"}

#defaults
subnet_to_scan = "203.135.63.0"
subnet_mask = "24"

TCP_CHECK = True
UDP_CHECK = False
ICMP_ECHO_CHECK = True

# TODO add options to change TCP/UDP/ICMP checks in command line
def updateWhiteList(ip,mask):
    #TODO put checks on ip and masks
    with open("zmapwhitelist.txt","wb") as f:
        f.write(ip+"/"+mask)
    print "whitelist file updated"
def inFiles(ip, data):
    final_list = []
    for key in data:
        final_list.append(int(ip in data[key]))
    return final_list

def mergeFiles(path_name,root_working_directory):
    
    os.chdir(path_name)
    all_files = []
    data = {}
    for fs in os.listdir(os.getcwd()):
        with open(fs, "rb") as f:
            data[fs.split(".")[0]] = f.read().split("\n")
    #print data
    # make a super set of all the ips
    super_set = []
    
    for key in data:
        all_files.append(key.split(".")[0])
        super_set = super_set + data[key]
    super_set = list(filter(lambda x: x != "", super_set))
    super_set = list(set(super_set))
    
    #print inFiles(super_set[0], data)
    final_data = []
    for ip in super_set:
        final_data.append([ip] + inFiles(ip,data))
    #print final_data
    print all_files
    file_name = "{}_report.csv".format(path_name)
    os.chdir(root_working_directory)

    with open(file_name, "wb") as finalFile:
        writer = csv.writer(finalFile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        writer.writerow(["IP"] + all_files)
        for row in final_data:
            writer.writerow(row)
        

    #print super_set

    
def main():
    # argument processing
    parser = argparse.ArgumentParser(description='Scan a subnet for open ports using zmap')
    parser.add_argument("IP", help="IP address of the subnet you want to scan, for example 192.168.0.0 for local network")
    parser.add_argument("Mask", help="Length of the subnet mask, for example /16 for local network")
    args = parser.parse_args()

    # update whitelist
    updateWhiteList(args.IP,args.Mask)
    # run zmap on listed ports
    root_working_directory = os.getcwd()
    
    path_name = "{}_{}".format(args.IP, args.Mask)
    if not os.path.exists(path_name):
        os.makedirs(path_name)
    
    
    if TCP_CHECK:
        os.chdir(path_name)
        os.system("echo \"Running Tcp scans...\"")
        for port in tcp_ports:
            print port, tcp_ports[port]
            command = "sudo zmap --target-port={} --max-targets=10000 --output-file=tcp_{}.csv --whitelist-file=../zmapwhitelist.txt".format(port,port)
            os.system(command)
    os.chdir(root_working_directory)
    
    if ICMP_ECHO_CHECK:
        os.chdir(path_name)
        os.system("echo \"Running ICMP scans...\"")
        command = "sudo zmap --output-file={}.csv --whitelist-file=../zmapwhitelist.txt --probe-module=icmp_echoscan".format("ICMP_ECHO")
        os.system(command)
    
    os.chdir(root_working_directory)
    if UDP_CHECK:
        # need to check on better ports?
        #TODO CHECK VALIDITY OF THESE SCANS
        os.chdir(path_name)
        os.system("echo \"Running UDP scans...\"")
        command = "sudo zmap -M udp -p 5632 --output-file={}.csv --whitelist-file=../zmapwhitelist.txt --probe-args=text:ST -N 100".format("UDP_5632")
        os.system(command)
        command = "sudo zmap -M udp -p 1434 --output-file={}.csv --whitelist-file=../zmapwhitelist.txt --probe-args=hex:02 -N 100".format("UDP_1434_hex02")
        os.system(command)
        command = "sudo zmap -M udp -p 1434 --output-file={}.csv --whitelist-file=../zmapwhitelist.txt --probe-args==file:netbios_137.pkt -N 100".format("UDP_1434_netbios")
        os.system(command)
        command = "sudo zmap -M udp -p 1434 --output-file={}.csv --whitelist-file=../zmapwhitelist.txt --probe-args=file:sip_options.tpl -N 100".format("UDP_1434_sip")
        os.system(command)
    os.chdir(root_working_directory)

    # merge all the files
    mergeFiles(path_name,root_working_directory)

    print "Done..."
    #print tcp_ports

main()