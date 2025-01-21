import argparse
import requests
import re
import subprocess
from fake_useragent import UserAgent
import urllib3
from pwn import log
from tabulate import tabulate
from termcolor import colored

urllib3.disable_warnings()

def filter_urls(url_list, extensions):
    ext_pattern = r"\.(" + "|".join(extensions) + r")($|\?)"
    return [url for url in url_list if re.search(ext_pattern, url)]


def count_extensions(url_list, extensions):
    counts = {ext: 0 for ext in extensions}
    for url in url_list:
        for ext in extensions:
            if url.endswith(f".{ext}") or f".{ext}?" in url:
                counts[ext] += 1
    return counts

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        print(f"\nPlease provide a domain using the --domain argument.\nUse --help for more information.")
        self.exit(2)

def parse_args():
    parser = CustomArgumentParser(description="Download files until a certain size limit is reached.")
    parser.add_argument('--domain', type=str, help="Domain to analyze (e.g., example.com)")
    parser.add_argument('--size', type=int, help="Size to download in MB")
    args = parser.parse_args()

    if not args.domain:
        parser.error("Missing required argument: --domain")

    return args


def main():
    args = parse_args()
    domain = args.domain
    size_limit_mb = args.size if args.size else None

    extensions_of_interest = [
        "xls", "xml", "xlsx", "json", "pdf", "sql", "doc", "docx", "pptx", "txt", "zip", "tar", 
        "gz", "tgz", "bak", "7z", "rar", "log", "cache", "secret", "db", "backup", "yml", "config", 
        "csv", "yaml", "md", "md5", "exe", "dll", "bin", "ini", "bat", "sh", "deb", "rpm", "iso", 
        "img", "apk", "msi", "dmg", "tmp", "crt", "pem", "key", "pub", "asc"
    ]

    ua = UserAgent()
    headers = {"user-agent": ua.chrome}

    wburl = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"

    print(f"Fetching URLs for *.{domain}* ...")
    response_logger = log.progress("Downloading URLs")
    size_logger = log.progress("Data downloaded")

    try:
        response = requests.get(wburl, headers=headers, stream=True, verify=False)

        if response.status_code != 200:
            response_logger.failure(f"Failed to fetch URLs. HTTP Status Code: {response.status_code}")
            return

        raw_urls = []
        total_size = 0

        size_limit_bytes = size_limit_mb * 1024 * 1024 if size_limit_mb else None

        for chunk in response.iter_content(chunk_size=1024):
            total_size += len(chunk)
            if size_limit_bytes and total_size > size_limit_bytes:
                break
            size_logger.status(f"{total_size} bytes downloaded / {size_limit_bytes if size_limit_bytes else 'N/A'} bytes")
            raw_urls.append(chunk.decode("utf-8", errors="ignore"))

        raw_urls = "".join(raw_urls)
        response_logger.success("URLs fetched successfully")
        size_logger.success(f"Total downloaded: {total_size} bytes")

        if size_limit_mb and total_size >= size_limit_bytes:
            size_logger.success(f"Download limit of {size_limit_mb} MB reached.")

    except Exception as e:
        response_logger.failure(f"Error occurred: {e}")
        return

    print("Running uro to deduplicate and clean URLs...")
    url_logger = log.progress("Processing URLs with uro")

    try:
        process = subprocess.Popen(
            ["uro"], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        deduplicated_urls, errors = process.communicate(input=raw_urls)

        if process.returncode != 0:
            url_logger.failure(f"uro command failed with error: {errors}")
            return

        deduplicated_urls = deduplicated_urls.splitlines()
        url_logger.success(f"Processed {len(deduplicated_urls)} unique URLs")
    except Exception as e:
        url_logger.failure(f"Error running uro: {e}")
        return

    print(f"Total unique URLs fetched: {len(deduplicated_urls)}")
    filtered_urls = filter_urls(deduplicated_urls, extensions_of_interest)

    print(f"Total URLs matching extensions of interest: {len(filtered_urls)}")

    extension_counts = count_extensions(filtered_urls, extensions_of_interest)

    table_data = []
    for ext, count in extension_counts.items():
        if count == 0:
            count_colored = colored(count, 'red')
        else:
            count_colored = colored(count, 'green')
        table_data.append([ext, count_colored])

    print(tabulate(table_data, headers=["Extension", "Occurrences"], tablefmt="pretty"))

    output_file = "info_disclosed_urls.txt"
    with open(output_file, "w") as f:
        f.write("\n".join(filtered_urls))

    print(f"Filtered URLs saved to {output_file}.")

if __name__ == "__main__":
    main()
