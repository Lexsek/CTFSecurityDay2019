import requests
import time


with open("hash_mmh3.txt", "r") as f:
    mmh3s = f.readlines()

token = "imsBs1Rs2jNk"
esgi = ".ctf.hacklab-esgi.org"

headers = {"User-Agent":"BadPunk"}

for mmh3 in mmh3s:
    domain = "https://{}{}{}/imsBs1Rs2jNk".format(token, mmh3.replace('\n',''), esgi)
    try:
        r = requests.get(domain, headers=headers, verify=False, timeout=2)
        if r.status_code == 200:
            print("Valid domain {} returned data {}".format(domain, r.text))
            break
    except:
        pass
