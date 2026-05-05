import sys
import shutil
import os

# Idk where these came from but EVERY patched build i've seen has had this specific change so i guess i'll follow the cult
original = "-invitesession -invitefrom -party_joininfo_token -replay".encode("utf-16-le")
patch    = "-log -nosplash -nosound -nullrhi -useolditemcards       ".encode("utf-16-le")

path = sys.argv[1]
if path[-1] != "/" and path[-1] != "\\":
    path = path + "/"

shipping_path = path + "FortniteGame/Binaries/Win64/FortniteClient-Win64-Shipping.exe"
if not os.path.exists(shipping_path + ".original"):
    print("Saving original file")
    shutil.copyfile(shipping_path, shipping_path + ".original")

f = open(shipping_path, "rb+")
data = f.read()
i = data.find(original)
if i == -1:
    print("Already patched")
    exit()

f.seek(i)
f.write(patch)
