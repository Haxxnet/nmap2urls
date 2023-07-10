import argparse
import os
import asyncio
import httpx
from libnmap.parser import NmapParser

async def extract_http_urls_from_nmap_xml(path):
    nmap_file = path

    report = NmapParser.parse_fromfile(nmap_file)
    urls = []

    async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(30.0)) as client:
        tasks = []
        for host in report.hosts:
            for service in host.services:
                if service.state == "open":
                    line = "http{s}://{hostname}:{port}"
                    line = line.replace("{hostname}", host.address if not host.hostnames else host.hostnames[0])
                    line = line.replace("{hostnames}", host.address if not host.hostnames else ", ".join(list(set(host.hostnames))))
                    line = line.replace("{ip}", host.address)
                    line = line.replace("{s}", "s" if (service.tunnel == "ssl" or "https" in service.service) else "")
                    line = line.replace("{port}", str(service.port))

                    if "http" in service.service:
                        urls.append(line)
                    else:
                        tasks.append(probe_url(client, line, urls))

        await asyncio.gather(*tasks)

    for url in list(dict.fromkeys(urls)):
        print(url)

async def probe_url(client, url, urls):
    try:
        r = await client.get(url)
        urls.append(url)
    except:
        try:
            if url.startswith('http://'):
                url = url.replace("http://", "https://")
            elif url.startswith('https://'):
                url = url.replace("https://", "http://")
           
            r = await client.get(url)
            urls.append(url)
        except:
            pass

def main():
    parser = argparse.ArgumentParser("nmap2urls.py")
    parser.add_argument("-f", "--file", help="path to an nmap xml file", required=True)
    args = parser.parse_args()

    if os.path.exists(args.file):
        try:
            asyncio.run(extract_http_urls_from_nmap_xml(args.file))
        except:
            print("[x] Error - Cannot process nmap xml file")
    else:
        print("[x] Error - Cannot find nmap xml file")

if __name__ == "__main__":
    main()
