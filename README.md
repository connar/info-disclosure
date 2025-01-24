# info-disclosure
The goal of this script is to try and find information disclosure vulnerabilities for a target domain.  
The way it does this is use the wayback machine for quick parsing (and not raising alerts) on a domain. It searches for specific filetypes that might contain sensitive information.  
After the urls containing the target filetype extensions have been found, you can try and browse them. If they do not exist today on the actual url, you can again use the wayback machine to try and download them from a previous snapshot.

# Setup - Clone the Repo
First, clone the repo:
```
git clone https://github.com/connar/info-disclosure.git
cd info-disclosure
```

# Setup - Install dependencies
After cloning the repo, install the dependencies that the script has:
```
pip install -r requirements.txt
```
Also, we need the  `uro` utility for further parsing of urls after getting them from the wayback machine:  
```
git clone https://github.com/s0md3v/uro.git
cd uro
python setup.py install
cp uro/uro.py /usr/bin
cp uro/uro.py /usr/sbin
```

# Run the script
After setting up the script, it can be run as:
```
python info-disclosure.py --domain <domain_name> --size <size_in_MB>
```

# Example
The following is an example output targeting the example.com:
```sh
└─$ python info-disclosure.py --domain example.com --size 500
Fetching URLs for *.example.com* ...
[+] Downloading URLs: URLs fetched successfully
[+] Data downloaded: Total downloaded: 54087122 bytes
Running uro to deduplicate and clean URLs...
[+] Processing URLs with uro: Processed 263958 unique URLs
Total unique URLs fetched: 263958
Total URLs matching extensions of interest: 5196
+-----------+-------------+
| Extension | Occurrences |
+-----------+-------------+
|    xls    |     29      |
|    xml    |    1518     |
|   xlsx    |     12      |
|   json    |     640     |
|    pdf    |     19      |
|    sql    |     10      |
|    doc    |     81      |
|   docx    |     60      |
|   pptx    |      7      |
|    txt    |    1250     |
|    zip    |     256     |
|    tar    |     14      |
|    gz     |     418     |
|    tgz    |     60      |
|    bak    |      6      |
|    7z     |      6      |
|    rar    |     12      |
|    log    |     39      |
|   cache   |      1      |
|  secret   |      1      |
|    db     |      6      |
|  backup   |      0      |
|    yml    |     21      |
|  config   |      4      |
|    csv    |     116     |
|   yaml    |     26      |
|    md     |     11      |
|    md5    |      0      |
|    exe    |     128     |
|    dll    |     40      |
|    bin    |     47      |
|    ini    |     39      |
|    bat    |     14      |
|    sh     |     56      |
|    deb    |     10      |
|    rpm    |     27      |
|    iso    |     41      |
|    img    |     23      |
|    apk    |     26      |
|    msi    |      4      |
|    dmg    |      5      |
|    tmp    |      1      |
|    crt    |     22      |
|    pem    |     44      |
|    key    |     14      |
|    pub    |      8      |
|    asc    |     25      |
+-----------+-------------+
Filtered URLs saved to info_disclosed_urls.txt.

─$ cat info_disclosed_urls.txt | grep -E ".zip"
http://example.com:80/compound.zip/compound-element.txt
http://example.com:80/downloads/myFiles.zip
http://example.com:80/example.zip
http://example.com:80/hoge.zip
...
...
...
```

## Searching for interesting words inside filetypes
Say you have found a bunch of `pdf/zip/docx/other` files and you want to quickly parse them to find suspicious words like "`Confidential/Secret/Private/Restricted/[other words]`" that could indicate an information disclosure vulnerability. To do so, you can use the following commands based on the filetype you want to parse:

**1 PDF Files (`.pdf`)**:
`cat all_urls.txt | grep -Ea '\.pdf' | while read -r url; do curl -s "$url" | pdftotext - - | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**2. Word Documents (`.doc`, `.docx`)**:
`cat all_urls.txt | grep -Ea '\.docx?$' | while read -r url; do curl -s "$url" | docx2txt /dev/stdin - | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**3. Excel Files (`.xls`, `.xlsx`)**:
`cat all_urls.txt | grep -Ea '\.xlsx?$' | while read -r url; do curl -s "$url" | xlsx2csv - | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**4. Text Files (`.txt`, `.log`, `.ini`, `.yml`, `.yaml`, `.md`, `.csv`)**:
`cat all_urls.txt | grep -Ea '\.(txt|log|ini|yml|yaml|md|csv)$' | while read -r url; do curl -s "$url" | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**5. Compressed Files (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`)**:
`cat all_urls.txt | grep -Ea '\.(zip|tar|gz|tgz|7z|rar)$' | while read -r url; do curl -s "$url" -o temp_compressed_file && unzip -p temp_compressed_file | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**6. SQL Files (`.sql`)**:
`cat all_urls.txt | grep -Ea '\.sql' | while read -r url; do curl -s "$url" | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**7. JSON Files (`.json`)**:
`cat all_urls.txt | grep -Ea '\.json' | while read -r url; do curl -s "$url" | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**8. Executable Files (`.exe`, `.bin`, `.dll`, `.msi`, `.apk`)**:
`cat all_urls.txt | grep -Ea '\.(exe|bin|dll|msi|apk)$' | while read -r url; do curl -s "$url" -o temp_executable_file && strings temp_executable_file | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

**9. Images (`.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`)**:
`cat all_urls.txt | grep -Ea '\.(jpg|jpeg|png|gif|bmp)$' | while read -r url; do curl -s "$url" -o temp_image_file && tesseract temp_image_file stdout | grep -Eaiq '(Interesting word 1|Interesting word 2|Interesting word 3| etc etc)' && echo "$url"; done`

### Reference
This script was inspire by the insane @LostSec. Props to him!  

