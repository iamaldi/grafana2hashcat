#!/usr/local/bin/python3
import argparse
import base64

"""
Name: Grafana2Hashcat
Description: Convert Grafana hashes to Hashcat's PBKDF2_HMAC_SHA256 format.
Author: github.com/iamaldi
"""

parser = argparse.ArgumentParser(description='Convert Grafana hashes to Hashcat\'s PBKDF2_HMAC_SHA256 format.')
parser.add_argument('hashes', help='Input file holding the Grafana hashes in the \'hash,salt\' format.')
parser.add_argument('-o', metavar="outfile", help='Output filename to save the Hashcat\'s PBKDF2_HMAC_SHA256 hashes. Default is stdout.')
args = parser.parse_args()

HASHCAT_PBKDF2_HMAC_SHA256_FORMAT = "sha256:10000:base64_salt:base64_digest"
hashcat_hashes = []

def read_file(filename: str):
    f = open(filename, "r")
    hashes = f.readlines()
    f.close()
    return hashes

def write_file(filename: str, hashcat_hashes: list):
    f = open(filename, "w")
    for hashcat_hash in hashcat_hashes:
        f.write(hashcat_hash + '\n')
    f.close()

def convert_hash(line: str):
    grafana_hash = line.rstrip('\n').split(',') # remove trailing newline character and split at the comma delimiter
    grafana_digest = grafana_hash[0]
    grafana_salt = grafana_hash[1]
    base64_salt = base64.b64encode(grafana_salt.encode('utf-8'))
    base64_digest = base64.b64encode(bytearray.fromhex(grafana_digest))
    
    hashcat_hash = HASHCAT_PBKDF2_HMAC_SHA256_FORMAT.replace("base64_salt", base64_salt.decode('utf-8'))
    hashcat_hash = hashcat_hash.replace("base64_digest", base64_digest.decode('utf-8'))
    return hashcat_hash

if __name__ == "__main__":
    print("\n[+] Grafana2Hashcat")
    print("[+] Reading Grafana hashes from: ", args.hashes)
    grafana_hashes = read_file(args.hashes)
    print("[+] Done! Read {total_hashes} hashes in total.".format(total_hashes = len(grafana_hashes)))

    print("[+] Converting hashes...")
    for grafana_hash in grafana_hashes:
        hashcat_hashes.append(convert_hash(grafana_hash))
    
    print("[+] Converting hashes complete.")
    if not args.o:
        print("[*] Outfile was not declared, printing output to stdout instead.\n")
        for entry in hashcat_hashes: print (entry)
        print("\n")
    else:
        print("[+] Writing output to '{outfile}' file.".format(outfile = args.o))
        write_file(args.o, hashcat_hashes)

    print("[+] Now, you can run Hashcat with the following command, for example:\n")
    print("hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt\n")