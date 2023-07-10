import argparse
import os
import httpx
from libnmap.parser import NmapParser

def extract_http_urls_from_nmap_xml(path):
    nmap_file = path 

    report = NmapParser.parse_fromfile(nmap_file)
    urls = []

    for host in report.hosts:
        for service in host.services:
            #if (service.state == "open") and ("http" in service.service):
            if (service.state == "open"):
                line = "http{s}://{hostname}:{port}"
                line = line.replace("{hostname}", host.address if not host.hostnames else host.hostnames[0]) # TODO: Fix naive code.
                line = line.replace("{hostnames}", host.address if not host.hostnames else ", ".join(list(set(host.hostnames)))) # TODO: Fix naive code.
                line = line.replace("{ip}", host.address)
                line = line.replace("{s}", "s" if (service.tunnel == "ssl" or "https" in service.service) else "")
                line = line.replace("{port}", str(service.port))

                # add url, if nmap already identified the port as http service
                if ("http" in service.service):
                    urls.append(line)
                # otherwise actively probe via httpx
                else:
                    try:
                        r = httpx.get(line, verify=False, timeout=3)
                        urls.append(line)
                    except Exception as e:
                        try:
                            if line.startswith('http://'):
                                line = line.replace("http://", "https://")
                            elif line.startswith('https://'):
                                line = line.replace("https://", "http://")
                            r = httpx.get(line, verify=False, timeout=3)
                            urls.append(line)
                        except Exception as e:
                            continue

    for url in list(dict.fromkeys(urls)):
        print(url)

def main():
    parser = argparse.ArgumentParser("nmap2urls.py")
    parser.add_argument("-f", "--file", help="path to an nmap xml file", required=True)
    args = parser.parse_args()

    if os.path.exists(args.file):
        try:
            extract_http_urls_from_nmap_xml(args.file)
        except:
            print("[x] Error - Cannot process nmap xml file")
    else:
        print("[x] Error - Cannot find nmap xml file")

if __name__ == "__main__":
    main()
