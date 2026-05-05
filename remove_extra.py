import os

f = open("extra_files.txt", "r")
files = f.readlines()
for file in files:
    os.remove(file.replace("\n", ""))
