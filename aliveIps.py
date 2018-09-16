#imports
import os
import csv

#globals
tcp_ports = {20:"FTP--Data",21:"FTP--Control",22:"SSH", 53:"DNS", 80:"HTTP", 118:"SQL--Service",443:"HTTPS"}



def inFiles(ip, data):
    final_list = []
    for key in data:
        final_list.append(int(ip in data[key]))
    return final_list

def mergeFiles(path_name,root_working_directory):
    os.chdir("tmp")
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
    file_name = "tmp/{}_ip_aliveness_report.csv".format(path_name)
    os.chdir(root_working_directory)

    with open(file_name, "wb") as finalFile:
        writer = csv.writer(finalFile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
        writer.writerow(["IP"] + all_files)
        for row in final_data:
            writer.writerow(row)

    return file_name.split("/")[1]    
    #print super_set

    
def check_aliveness(whitelist_file,TCP_CHECK = False,UDP_CHECK =False,ICMP_ECHO_CHECK=False):
    # run zmap on listed ports
    root_working_directory = os.getcwd()
    
    path_name = whitelist_file.split("_")[0]
    
    if not os.path.exists("tmp"):
        os.makedirs("tmp")
    
    os.chdir("tmp")

    if not os.path.exists(path_name):
        os.makedirs(path_name)
    if TCP_CHECK:
        os.chdir(path_name)
        os.system("echo \"Running Tcp scans...\"")
        for port in tcp_ports:
            command = "sudo zmap --target-port={} --max-targets=10000 --output-file=tcp_{}.csv --whitelist-file=../{}".format(port,port,whitelist_file)
            #print command
            os.system(command)
    os.chdir("..")

    
    if ICMP_ECHO_CHECK:
        os.chdir(path_name)
        os.system("echo \"Running ICMP scans...\"")
        command = "sudo zmap --output-file={}.csv --whitelist-file=../{} --probe-module=icmp_echoscan".format("icmp_echo",whitelist_file)
        os.system(command)
        
    os.chdir("..")
    if UDP_CHECK:
        #TODO CHECK VALIDITY OF THESE SCANS
        # need to check on better port?
        os.chdir(path_name)
        os.system("echo \"Running UDP scans...\"")
        command = "sudo zmap -M udp -p 33470 --output-file={}.csv --whitelist-file=../{} -N 100".format("udp_33470",whitelist_file)
        os.system(command)

    os.chdir(root_working_directory)
    # merge all the files
    return mergeFiles(path_name,root_working_directory)
    print "Done..."
    
    #print tcp_ports

