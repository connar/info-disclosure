# info-disclosure
This script is used for information disclosure vulnerabilities on a target domain.  
It utilizes the wayback machine to get all crawled urls and files of the specified domain and subdomains.  
So even if we would normally get a 404 error on a file, through the wayback machine we might be lucky enough to get it back.

# Setup - Clone the Repo
First, clone the repo:
```
git clone <repository_url>
cd <repository_directory>
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



### Reference
This script was inspire by the insane @LostSec. Props to him!  

