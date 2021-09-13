# Upload 5.0 records
# For now, update directories appropriately
import sys
import json
import getopt
from cve4to5up import CVE_Convert


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hi:u:d:", ["icvefile=","iuserfile=","ocvedir="])
    except getopt.GetopError:
        print ('USAGE python UpdateCveAssignerv5.py -i <inputcvefile> -u <inputuserfile> -d <CvesOutputDir>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            sys.exit()
        elif opt in ("-i", "--icvefile"):
            inputCveFile = arg
        elif opt in ("-u", "--iuserfile"):
            inputUserFile = arg
        elif opt in ("-d", "--ocvedir"):
            outputpath = arg
    with open(inputCveFile, 'r+') as cves, open(inputUserFile) as users:
        cve_list = json.load(cves)
        user_list = json.load(users)
        for cve in cve_list:
            assigner = cve['cve']['CVE_data_meta']['ASSIGNER']
            id = cve['cve']['CVE_data_meta']['ID']
            # mitre org
            new_assigner = "9845b82e-47a9-4fe7-8908-68646f952267"
            for user in user_list:
                if assigner == user['username']:
                    new_assigner = user['org_UUID']
            
            with open('temp.json', 'a+') as f:
                f.seek(0)
                f.truncate()
                json.dump(cve['cve'], f)

            CVE_Convert('temp.json', 'test-script-results/', new_assigner)
            with open(f'{outputpath}/{id}.json') as f:
                json_data = json.load(f)
                cve['cve'] = json_data
        cves.seek(0)
        json.dump(cve_list, cves, indent=4)
        cves.truncate()


if __name__ == "__main__":
   main(sys.argv[1:])