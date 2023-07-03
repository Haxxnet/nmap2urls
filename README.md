# nmap2urls
Python3 script to extract HTTP/S URLs from an Nmap XML file

![image](https://github.com/Haxxnet/nmap2urls/assets/21357789/47e547ee-33f1-48a6-82cc-795cc88149f0)

## Usage

````
usage: nmap2urls.py [-h] -f FILE

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  path to an nmap xml file
````

## Example

````
# installation
git clone https://github.com/Haxxnet/nmap2urls && cd nmap2urls
pip install -r requirements.txt

# extracting urls from nmap file
python3 nmap2urls.py --file my_nmap_scan.xml
````

