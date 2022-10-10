import requests
import json
from bs4 import BeautifulSoup
import time
import random
import urllib.request
import os
import time

os.system("export ALL_PROXY=socks5://127.0.0.1:1080")

nvd_url = "https://nvd.nist.gov/vuln/detail/"

html_path = "./html_nvd"
if not os.path.exists(html_path):
    os.mkdir(html_path)

cve_kernel_url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=Linux+Kernel'
r = requests.get(url=cve_kernel_url)
soup = BeautifulSoup(r.text,'lxml')


cve_id_lst = []
links = soup.find_all('a')
for link in links:
	if link['href'][0:8] == '/cgi-bin':
		cve_id_lst.append(link.get_text())

cves = []
i = 0
err_times = 0
while i < len(cve_id_lst):
    cve_id = cve_id_lst[i].upper()
    if cve_id[4:8] > '2010':
        break

    file_path = html_path + "/" + cve_id + ".html"

    time.sleep(random.randint(2, 6))
    try:
        os.system("wget " + nvd_url + cve_id + " -O " + html_path + "/" + cve_id + ".html")
    except Exception as e:
        err_times += 1
        if err_times > 5:
            err_times = 0
            i += 1
            with open("err_M3.log", "a") as f:
                f.write(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
                f.write("\n")
                f.write(cve_id)
                f.write("\n")
                f.write(str(e))
                f.write("\n\n")
    i += 1



