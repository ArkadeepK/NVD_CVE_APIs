#!/usr/bin/python3
import json
import time
import requests
import datetime
from datetime import timedelta
import collections
from collections import OrderedDict

print("Hello CVSS SIG\n")

API_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/" #Base API address on NVD
vendors = ["microsoft","google","cisco","juniper","oracle","ibm","intel"] #List of vendors
#vendors = ["intel","dell"] #List of vendors
resultsPerPage = "2000" # assuming that none of the response will include more that 2000 results. current search window is 90 days for 1 vendor. Might need change, if the search window is incresed.
data_window_years = 4

for vendor in vendors:
    now = datetime.datetime.now() - timedelta(days=1) # looking back "data_window_years" years from current date
    iters = int(data_window_years*360/90) #each iter will check 90 days iteration window. 360 days per year. Rounding off
    pubEndDate = now
    pubStartDate = pubEndDate - timedelta(days=90) #setting up 90 days of CVE publication (NOT modification) window. Maximum allowed window in 120 days
    CVSS_List = [] #container to keep CVSSv3 scores
    for di in range(1,iters+1):
        req = API_url + "?pubStartDate=" + pubStartDate.strftime("%Y-%m-%d") + "T00:00:00:000%20UTC&pubEndDate=" + pubEndDate.strftime("%Y-%m-%d") + "T00:00:00:000%20UTC&cpeMatchString=cpe:2.3:*:" + vendor + ":*:*:*:*:*:*:*:*:*&resultsPerPage="+ resultsPerPage
        #print(req) # for debugging
        rsp = requests.get(req) #fetching the JSON response from NVD
        time.sleep(1) # adding delay to avoid throttling from NVD
        try:
            j = json.loads(rsp.text)
        except Exception as e: #NVD is sometimes sending a abruptly truncated response
            print("json loading failed with Exception",e)
            print("JSON response from NVD",rsp.text)
        CVE_Items = j["result"]["CVE_Items"]
        for cve in CVE_Items:
            try:
                if vendor.lower() in cve["cve"]["CVE_data_meta"]["ASSIGNER"].lower(): #ignoring third party CVEs. e.g. Adobe vulnerability impacting product ruiing on Microsoft, like CVE-2021-40728
                    CVSS_List.append(cve["impact"]["baseMetricV3"]["cvssV3"]["baseScore"])
            except Exception as e: #ignoring malformed CVE records in NVD response
                print("Error : ",e)
                print("Skipping :",cve["cve"]["CVE_data_meta"]["ID"])
        pubStartDate = pubStartDate - timedelta(days=90) #shifting the iteration window
        pubEndDate = pubEndDate - timedelta(days=90) #shifting the iteration window
    print("Approx CVEs published by",vendor,"in",data_window_years,"years, having CVSSv3 score =",len(CVSS_List))
    count = dict(collections.Counter(CVSS_List)) #creating a histogram in dictionary format
    count_sorted = dict(OrderedDict(sorted(count.items()))) #sorting the histogram based on keys
    print("Number of Distinct CVSSv3 numeric scores :",len(count_sorted))
    print("Histogram :",count_sorted, "\n")