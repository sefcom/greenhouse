import os, stat
import shutil
import subprocess
import hashlib
import pathlib
import time

class Files():
    def mkdir(path, root="/", silent=False):
        recursive_dirs = []
        if os.path.exists(path):
            Files.rm_target(path, silent)
        while len(path) > 0 and not os.path.exists(path):
            if not silent:
                print("    - **", path)
            if os.path.islink(path):
                # path = os.path.realpath(path)
                oldpath = path
                path = str(pathlib.Path(path).resolve())
                if not path.startswith(root):
                    Files.rm_target(oldpath)
                    path = oldpath
            else:
                recursive_dirs.append(path)
                path = os.path.dirname(path)
        if not silent:
            print("Recursive Dirs:")
            print("     - ", recursive_dirs)
        try:
            for dirs in recursive_dirs[::-1]: #iterate from lowest dir
                if not silent:
                    print("    - Making directory", dirs)
                prev_dir = os.path.dirname(dirs)
                if os.path.exists(prev_dir) and not os.path.isdir(prev_dir):
                    if not silent:
                        print("      - Changing file into directory", prev_dir)
                    Files.rm_file(prev_dir)
                    os.mkdir(prev_dir)
                os.mkdir(dirs)
        except Exception as e:
            print(e)

    def touch_file(path, root="/", silent=False):
        try:
            basedir = os.path.dirname(path)
            if not os.path.exists(basedir) or not os.path.isdir(basedir):
                Files.mkdir(basedir, root=root)
            if not os.path.exists(path):
                if not silent:
                    print("    - Touching file", path)
                os.mknod(path)
        except Exception as e:
            print(e)

    def write_file(path, value, root="/", silent=False):
        if not silent:
            print("    - Writing file %s with value %s" % (path, value))
        try:
            if not os.path.exists(path):
                Files.touch_file(path)
            with open(path, "w") as wfile:
                wfile.write(value)
            wfile.close()
        except Exception as e:
            print(e)

    def rm_target(path, silent=False):
        if os.path.isdir(path) and not os.path.islink(path):
            Files.rm_folder(path, silent)
        else:
            Files.rm_file(path, silent)

    def rm_files(pathlist, silent=False):
        for path in pathlist:
            Files.rm_file(path, silent)

    def rm_file(path, silent=False):
        if os.path.isdir(path) and not os.path.islink(path):
            print("    - Is a Directory, skipping", path)
            return
        if os.path.exists(path):
            if not silent:
                print("    - Deleting file", path)
            os.remove(path)
        elif os.path.islink(path):
            if not silent:
                print("    - Unlinking file", path)
            os.unlink(path)
            

    def rm_folder(path, ignore_errors=False, silent=False):
        retry = 0
        if os.path.exists(path):
            if not silent:
                print("    - Recursively deleting folder", path)
            while retry < 3:
                try:
                    shutil.rmtree(path, ignore_errors=ignore_errors)
                    break
                except OSError as e:
                    print(e)
                    time.sleep(1)
                    retry += 1
                    continue
        else:
            print("    - Folder path not found:", path)

    def mk_link(linkpath, linktarget, relative_dir="."):
        fullpath = os.path.join(relative_dir, linktarget)
        if linkpath == fullpath:
            print("    - not creating symlink that points to itself. Skip")
            return
        current_dir = os.getcwd()
        os.chdir(relative_dir)
        Files.rm_file(linkpath)
        os.symlink(linktarget, linkpath)
        os.chdir(current_dir)

    def find_file_paths(folder, target):
        paths = []
        for root, dirs, files in os.walk(folder):
            for f in files:
                if target == f:
                    path = os.path.join(root, f)
                    paths.append(path)
        return paths

    def copy_overwrite_dir_contents(src, dest):
        if not os.path.exists(src):
            print("src", src, "does not exist")
            return
        if not os.path.isdir(src):
            print("src", src, "is not a directory")
            return
        if not os.path.exists(dest):
            print("dest", dest, "does not exist")
            return
        if not os.path.isdir(dest):
            print("dest", dest, "is not a directory")
            return
        for f in os.listdir(src):
            path = os.path.join(src, f)
            print("     - copying %s" % (path))
            subprocess.call(["cp", "-r", path, dest])

    def copy_directory(src, dest, via_cp=False):
        if os.path.exists(dest):
            Files.rm_folder(dest)
        if via_cp:
            subprocess.run(["cp", "-r", "-R", src, dest])
        else:
            shutil.copytree(src, dest, symlinks=True)

    def copy_file(src, dest, silent=False):
        st_mode = 0
        if os.path.exists(src):
            st_mode = os.stat(src).st_mode
        if os.path.exists(dest):
            Files.rm_file(dest, silent=True)
        if not silent:
            print("    - Copying file", src, "to", dest)
        shutil.copyfile(src, dest)
        os.chmod(dest, st_mode | stat.S_IXUSR)

    def get_all_files(folder):
        paths = []
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f not in paths:
                    path = os.path.join(root, f)
                    paths.append(path)
        return paths

    def hash_file(path):
        result = None
        if not os.path.exists(path):
            print("    - error, file does not exist!")
            return result
        with open(path,"rb") as hashfile:
            fbytes = hashfile.read()
            result = hashlib.sha256(fbytes).hexdigest();
        return result