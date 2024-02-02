import vt
import sys

try:
    file_hash = sys.argv[1]
except IndexError:
    print("ERROR: You must supply a file hash.")
    sys.exit(1)

# //// VIRUSTOTAL API KEY ////
API = # CHANGE THIS TO YOUR VIRUSTOTAL API KEY

client = vt.Client(API)

file = client.get_object(f"/files/{file_hash}")

analysis = file.last_analysis_stats

for x,y in analysis.items():
    print(x.title(),":",y)

client.close()