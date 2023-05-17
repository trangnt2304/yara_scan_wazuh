
import os
import yara
import hashlib
import time
import sys

def hash_file(filename):
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           sha1.update(chunk)
           md5.update(chunk)
           sha256.update(chunk)
    print("MD5: {0}".format(md5.hexdigest()))
    print("SHA1: {0}".format(sha1.hexdigest()))
    print("SHA256: {0}".format(sha256.hexdigest()))

def scan_file(file_source, file_rules): 
    match_list = []
    try:
        file_size = round((os.path.getsize(file_source) / 1048576), 4)
        if(file_size < 30):
            print("Quet file: {0}".format(file_source))
            hash_file(file_source)
            match_list = []
            rules = yara.compile(filepaths=file_rules)
            with open(file_source, 'rb') as f:
                matches = rules.match(data=f.read(),timeout=60)
            if len(matches) > 0:
                match_list.append(matches)
            print(matches)
        else:   
            print("File lon hon 30Mb: {0}".format(file_source))
    except OSError:
        print('OSError')
    except RuntimeWarning:
        print('RuntimeWarning')
    return match_list
    
def scan_folder(dir_source, file_rules): 
    countFileNumber = 0
    match_list = []
    try:
        print("Quet folder: {0}".format(dir_source))
        for root, dirs, files in os.walk(dir_source):
             for file in files:
                full_path = os.path.join(root, file)
                if(len(scan_file(full_path,file_rules)) != 0):
                    countFileNumber = countFileNumber + 1
        print('So file da quet:')
        print(countFileNumber)
    except OSError:
        print('OSError')
    except RuntimeWarning:
        print('RuntimeWarning')
    return match_list


def main(argv):
    print(argv)
   # input
    try:
        if os.path.isfile(argv):
            print("Kết quả quét: ")
        # file exists
            scan_file(argv,res)
        elif os.path.isdir(argv):
            print("Kết quả quét: ")
        # directory exists
            scan_folder(argv,res)
        else:
            print("Không tồn tại file/dir này")
    except FileExistsError:
        print('FileExistsError')
    except FileNotFoundError:
        print('FileNotFoundError')

# Get rules
count = 0
fileDir = [""]
fileDirKey =[]
for root, dirs, files in os.walk("D:\yara_rule_collected\collected_by_git"):
    for file in files:
        full_path = os.path.join(root, file)
        if full_path.endswith(".yar"):
            count = count+1
            fileDirKey.append(str(count))
            fileDir.append(os.path.join(root, file))
tuples = [(key, value)
		for i, (key, value) in enumerate(zip(fileDirKey, fileDir))]
res = dict(tuples)
if '1' in res: res.pop('1')
print("So luong rules yara: {0}".format(len(res)))   

main(sys.argv[1])