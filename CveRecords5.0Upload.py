# Upload 5.0 records
# Global variables should be set appropiately, and a directory of json 5.0 files must be given
import sys
import getopt
import os.path
import json
import requests

RSUS_URL = ''
CVE_API_USER = ''
CVE_API_KEY = ''
CVE_API_ORG = ''

def main(argv):
    inputPath = ''
    try:
        opts, args = getopt.getopt(argv, "hi:", ["ifile="])
    except getopt.GetopError:
        print ('USAGE python cve4to5up.py -i <inputdirectory')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputPath = arg
    if inputPath:
        for subdir, dirs, files in os.walk(inputPath):
            for file in files:
                with open(inputPath + '/' + file) as json_file:
                    data = json.load(json_file)
                    cve_id = data.get('cveMetadata', {}).get('id')
                    params = {'id': cve_id}
                    headers = {'CVE-API-USER': CVE_API_USER,
                        'CVE-API-ORG': CVE_API_ORG,
                        'CVE-API-KEY': CVE_API_KEY,
                        'Content-Type': "application/json"}
                    r = requests.put(
                        RSUS_URL + cve_id,
                        headers=headers,
                        data=json.dumps(data)
                    )
                    

if __name__ == "__main__":
   main(sys.argv[1:])