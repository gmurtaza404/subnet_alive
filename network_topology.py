# main driver file

#imports
import resolve
import aliveIps
import findPaths
import argparse


















def main():
    #argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_name" ,help="domain name you want to scan and make topology of.")
    args = parser.parse_args()

    #actual pipeline
    allocated_subnets = resolve.resolve_domain(args.domain_name)
    
    if allocated_subnets != "failed":
        aliveness_report = aliveIps.check_aliveness(allocated_subnets)
        findPaths.findPaths(aliveness_report)
        print "Done..."
    else:
        print "Invalid Domain name"
        exit(1)
main()