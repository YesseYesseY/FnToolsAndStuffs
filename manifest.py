import struct
import zlib
import io
import sys
import os
import hashlib

def read_int32(f):
    return struct.unpack("<i", f.read(4))[0]

def read_uint32(f):
    return struct.unpack("<I", f.read(4))[0]

def read_uint8(f):
    return struct.unpack("<B", f.read(1))[0]

def read_string(f):
    str_size = read_int32(f)
    if str_size == 0:
        return ""

    str_data = f.read(str_size)
    return str_data[:-1].decode()

MAGIC = 0x44BEC00C

if len(sys.argv) < 3:
    exit()

path = sys.argv[1]
f = open(path, "rb")
if struct.unpack("<i", f.read(4))[0] != MAGIC:
    print("Wrong Magic")
    exit()

header_size = read_uint32(f)
data_size_uncompressed = read_uint32(f)
data_size_compressed = read_uint32(f)
f.read(20); # FSHAHash = SHA-1
stored_as = read_uint8(f)
compressed = stored_as == 1 # Idc about encrypted manifests
version = read_int32(f)
f.seek(header_size)
compressed_data = f.read()
data = io.BytesIO(zlib.decompress(compressed_data))

# print(header_size)
# print(data_size_uncompressed)
# print(data_size_compressed)
# print(stored_as)
# print(compressed)
# print(version)
# print(len(compressed_data))
# print("--------------")

# Meta
meta_size = read_uint32(data)
meta_version = read_uint8(data)
feature_level = read_int32(data)
is_file_data = read_uint8(data) == 1
app_id = read_uint32(data)
app_name = read_string(data)
build_version = read_string(data)
launch_exe = read_string(data)
launch_command = read_string(data)
prereq_size = read_int32(data)
for i in range(prereq_size):
    read_string(data)
prereq_name = read_string(data)
prereq_path = read_string(data)
prereq_args = read_string(data)
if meta_version >= 1:
    build_id = read_string(data)
if meta_version >= 2:
    uninstall_path = read_string(data)
    uninstall_args = read_string(data)

# print(meta_size)
# print(meta_version)
# print(feature_level)
# print(is_file_data)
# print(app_id)
# print(app_name)
# print(build_version)
# print(launch_exe)
# print(launch_command)
# print(prereq_size)
# print(prereq_name)
# print(prereq_path)
# print(prereq_args)
# if meta_version >= 1:
#     print(build_id)
# if meta_version >= 2:
#     print(uninstall_path)
#     print(uninstall_args)
# print("-------------")

cdl_size = read_uint32(data)
cdl_version = read_uint8(data)
cdl_element_version = read_uint32(data)
for i in range(cdl_element_version):
    data.read(16) # FGuid
    data.read(8) # uint64
    data.read(20) # FSHAHash
    data.read(1) # uint8
    data.read(4) # uint32
    data.read(8) # int64

# print(cdl_size)
# print(cdl_version)
# print(cdl_element_version)
# print("------------")

fml_size = read_uint32(data)
fml_version = read_uint8(data)
fml_element_count = read_uint32(data)

# print(fml_size)
# print(fml_version)
# print(fml_element_count)

man_files = []
for i in range(fml_element_count):
    man_files.append({
        "name": read_string(data)
    })

for i in range(fml_element_count):
    man_files[i]["symlink_target"] = read_string(data)
for i in range(fml_element_count):
    man_files[i]["hash"] = data.read(20).hex()
for i in range(fml_element_count):
    man_files[i]["flags"] = read_uint8(data)
for i in range(fml_element_count):
    arr = []
    arr_size = read_int32(data)
    for j in range(arr_size):
        arr.append(read_string(data))
    man_files[i]["install_tags"] = arr
# for i in range(fml_element_count):
#     data.read(24) # FGuid + uint32 + uint32

#                                  FortniteGame/Content/Paks/pakchunk1000-WindowsClient.pak
# /home/yes/WinApps/26.30/Fortnite/FortniteGame/Content/Paks/pakchunk1000-WindowsClient.pak

extra_files = []
wrong_hash_count = 0

print(man_files[-20])
for root, dirs, walk_files in os.walk(sys.argv[2]):
    for file in walk_files:
        full_path = os.path.join(root, file)

        found = False
        for man_file in man_files:
            if full_path.endswith(man_file["name"]):
                found = True
                mhash = man_file["hash"]
                fhash = hashlib.sha1()
                with open(full_path, "rb") as f:
                    while True:
                        fd = f.read(1024 * 1024 * 1024)
                        if not fd:
                            break
                        fhash.update(fd)

                if mhash != fhash.hexdigest():
                    print(f"\033[31mWrong hash on {full_path}\033[0m")
                    wrong_hash_count += 1
                else:
                    print(f"\033[32mCorrect hash on {full_path}\033[0m")

        if not found:
            extra_files.append(full_path)

print(f"{wrong_hash_count} wrong hashes found")
print(f"{len(extra_files)} extra files found, writing to extra_files.txt")
with open("extra_files.txt", "w") as f:
    for file in extra_files:
        f.write(file)
        f.write("\n")
