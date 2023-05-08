# fortigate-cis-compliance-script
A python script to check a FortiGate for CIS compliance 

Install:

pip install -r requirements.txt


Usage:
config file: main.py -i fortigate_backup.conf -o result.csv
API method: main.py -u https://10.10.10.10/ -k 1a1a1a1a-2b2b2b2b2-3c3c3c3c3 -o result.csv

options:
  -h, --help            show this help message and exit
  -i INFILE, --infile INFILE
                        Specify the path of the config file for the fortigate that you want to scan
  -u URL, --url URL     Specify the URL to that exposed if checking the fortigate using the API
  -k KEY, --key KEY     Specify the API key to use if checking the fortigate using the API
  -o OUTFILE, --outfile OUTFILE
                        Specify the path of the CSV file to dump the results to. if not specified you will only see results in the terminal.
