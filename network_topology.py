# main driver file

#imports
import resolve
import aliveIps
import argparse


















def main():
    #argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_name" ,help="domain name you want to scan and make topology of.")
    args = parser.parse_args()

    #actual pipeline
    filename = resolve.resolve_domain(args.domain_name)
    if filename != "failed":
        aliveIps.check_aliveness(filename)
    else:
        print "Invalid Domain name"
        exit(1)
main()