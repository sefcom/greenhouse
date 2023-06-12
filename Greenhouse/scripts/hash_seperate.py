import os
import hashlib
from argparse import ArgumentParser

def calculate_hash_val(path, block_size=''):
    file = open(path, 'rb')
    hasher = hashlib.md5()
    data = file.read()
    while len(data) > 0:
        hasher.update(data)
        data = file.read()
    file.close()
    return hasher.hexdigest()

def sort_files(target_fs, extra_fs):
    hashes = set()
    for root, dirs, files in os.walk(target_fs, topdown=False):
        for f in files:
            path = os.path.join(root, f)
            md5 = calculate_hash_val(path)
            if md5 in hashes:
                newpath = os.path.join(extra_fs, f)
                os.rename(path, newpath)
                print("   - moving ", path, "to", newpath)
            else:
                hashes.add(md5)


if __name__ == "__main__":
    parser = ArgumentParser(description='sort_files and move duplicate hashes')
    parser.add_argument('-t', metavar='TARGET_FOLDER', type=str, help='The target folder path', required=True)
    parser.add_argument('-f', metavar='EXRA_FOLDER', type=str, help='The folder to store duplicates', required=True)
    args = parser.parse_args()
    sort_files(args.t, args.f)