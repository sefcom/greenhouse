import os, sys


brand = ""
path = ""
name = ""
sha256sum = ""
extracted = False
canrun = False
curlpassed = False
webpassed = False

def process_log_dump(LOGPATH, iid):
    global brand, name, path, sha256sum
    global extracted, canrun, curlpassed, webpassed

    lineCount = 0
    targetPath = os.path.join(LOGPATH, iid)
    if not os.path.exists(targetPath):
        print(targetPath, "doesnt exist")
        return
    with open(targetPath, "rb") as bFile:
        for line in bFile:
            lineCount += 1
            try:
                line = line.decode('utf-8',errors='ignore')
                if "PATCH LOOP [0]" in line:
                    extracted = True
                if "TARGET HASH" in line:
                    sha256sum = line.split(":")[1].strip()
                if not curlpassed and "failed to parse trace_path" in line:
                    canrun = False
                if "parse completed!" or "[GreenHouseQEMU] IP" in line or curlpassed:
                    canrun = True
                if "[connected]: True" in line:
                    curlpassed = True
                if "[wellformed]: True" in line:
                    webpassed = True
                if line.startswith("copying "):
                    path = line.split()[1]
                    name = path.split("/")[-1] # .rsplit(".", 1)[0]
                    name = name.replace("(", "_").replace(")", "_").replace("-", "_")
                    dirpath = os.path.dirname(path)
                    brand = dirpath.split("/")[-1].split("_")[0].strip()
            except Exception as e:
                print(e)
                print(traceback.format_exc())
                print("Line: ", lineCount)
                ()
                exit()
    bFile.close()

def reset():
    global brand
    global path
    global name
    global extracted
    global canrun
    global curlpassed
    global webpassed
    global sha256sum

    brand = ""
    path = ""
    name = ""
    sha256sum = ""
    extracted = False
    canrun = False
    curlpassed = False
    webpassed = False

def main(LOGPATH, NUM_TARGETS):
    print("BRAND,HASH,NAME,Unpack,Execute,Connect,Interact")
    for i in range(1, NUM_TARGETS+1):
        iid = str(i)
        reset()
        process_log_dump(LOGPATH, iid)
        print("%s,%s,%s,%s,%s,%s,%s" % (brand, sha256sum, name, extracted, canrun, curlpassed, webpassed))


if len(sys.argv) < 2:
    print("process_logs.py <path-to-log-folder>")
    exit()

LOGPATH = sys.argv[1]
#print("Processing", LOGPATH)

if not os.path.exists(LOGPATH):
    print("%s doesn't exist" % LOGPATH)
    exit()
    
NUM_TARGETS = len(os.listdir(LOGPATH))

main(LOGPATH, NUM_TARGETS)
