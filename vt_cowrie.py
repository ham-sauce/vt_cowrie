import vt
import csv
import hashlib
import time
from pathlib import Path

# //// VIRUSTOTAL API KEY ////
API = # CHANGE THIS TO YOUR VIRUSTOTAL API KEY

client = vt.Client(API)


# Function to get the basic info from VirusTotal
def get_vt_info(file_hash):
    try:
        file = client.get_object(f"/files/{file_hash}")
    except vt.error.APIError:
        return [file_hash, 0, 0, 0, 0, 0, "Not Found"]
        
    analysis = file.last_analysis_stats
    date = file.last_analysis_date.strftime("%d %b %Y")
    
    return [
        file_hash,
        analysis['malicious'],
        analysis['suspicious'],
        analysis['undetected'],
        analysis['harmless'],
        analysis['failure'],
        date
    ]


# Funtion to get the SHA256 of a file using the file path as input
def get_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# Function that checks to see if the hash_list.txt exists
# If not, it creates it and adds all of the filenames from the downloads directory.
# Otherwise it checks the list and appends any not already in the list. 
def get_hashes():
    downloads = Path("/srv/cowrie/var/lib/cowrie/downloads/")
    files = [file for file in downloads.glob('*') if file.is_file()]
    hash_list = []
    for file in files:
        if len(str(file.name)) == 64:
            hash_list.append(str(file.name))
        else:
            hash_list.append(get_sha256(file))
        
    hash_path = Path("./hash_list.txt")
    if not hash_path.exists():
        with open("./hash_list.txt", "w") as file:
            for line in hash_list:
                file.write(line + "\n")
    else:
        with open("./hash_list.txt", "r") as file:
            existing_hashes = file.read()
        with open("./hash_list.txt", "a") as file:
            for line in hash_list:
                if line not in existing_hashes:
                    file.write(line + "\n")

get_hashes()

# checks the directory in which program was ran to see if the csv exists
# if not, it creates it and adds the heading
info_path = Path("./vt_info.csv")
if not info_path.exists():
    with open("./vt_info.csv", "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["FILE HASH", "MALICIOUS", "SUSPICIOUS", "UNDETECTED", "HARMLESS", "FAILURE", "DATE LAST ANALYSIS"])


# function to iterate over the list of hashes to query VT and add to a DB
def add_db():
    with open("./hash_list.txt", "r") as file:
        hashes = file.readlines()
    
    # This de-duplicates any hashes in hash_list.txt
    unique_hashes = set(hash.strip() for hash in hashes)
 
    vt_info = Path("./vt_info.csv")
    column_1 = []
    with open(vt_info, "r") as file:
        reader = csv.reader(file)
        for row in reader:
            column_1.append(row[0])

    with open("./vt_info.csv", "a", newline='') as file:
        writer = csv.writer(file)
        for hash in unique_hashes:
            if hash.strip() not in column_1:
                print(f"Gathering info for {hash.strip()}")
                writer.writerow(get_vt_info(hash.strip()))
                time.sleep(15)

add_db()


# The next two functions are just formatting the csv to be more readable in the terminal.
def pad_col(col, max_width):
    return col.ljust(max_width)

def create_report():
    with open('./vt_info.csv') as csvfile:
        reader = csv.reader(csvfile)
        all_rows = []
        for row in reader:
            all_rows.append(row)

    max_col_width = [0] * len(all_rows[0])
    for row in all_rows:
        for idx, col in enumerate(row):
            max_col_width[idx] = max(len(col), max_col_width[idx])

    with open("cowrie_downloads_report.txt", "w") as f:
        for row in all_rows:
            to_print = ""
            for idx, col in enumerate(row):
                to_print += pad_col(col, max_col_width[idx]) + " | "
            f.writelines("-"*len(to_print) + "\n")
            f.writelines(to_print + "\n")

create_report()

client.close()