#!/opt/splunk/bin/python
"""
Description:
- Make requests to the domains retrieved from urlscan.io
- Recursively download the site when an open directory hosting a file with the desired file extension

3 positional arguments needed:
- Query Type : automatic, manual, certstream, openphish, phishtank, twitter, urlhaus
- Delta : Number of days back to search (GMT)
- File Extension : 7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip

Optional arguments:
- --dryrun  : Perform a test run to see what would be downloaded
- --exclude : A comma-separated list of domains to not download content from (ex. 'google.com,bing.com')
- --timeout : Set time to wait for a connection
- --tor     : Download files via the Tor network

Credit: https://github.com/ninoseki/miteru

Resources:
    http://docs.python-requests.org/en/master/user/advanced/#proxies
    https://gist.github.com/jefftriplett/9748036
    https://ec.haxx.se/libcurl-proxies.html

Usage:

```
python opendir_urlscan.py <QUERY_TYPE> <DELTA> <FILE_EXTENSION> [--dry-run] [--exclude=CSV]
```

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
from collections import OrderedDict
from datetime import datetime
from datetime import timedelta
import glob
import os
import subprocess
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
from termcolor import colored, cprint
import yaml


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories on urlscan.io.")
parser.add_argument(metavar="query type",
                    dest="query_type",
                    choices=["automatic", "manual", "certstream", "openphish", "phishtank", "twitter", "urlhaus"],
                    help="automatic, manual, certstream, openphish, phishtank, twitter, urlhaus")
parser.add_argument(dest="delta",
                    type=int,
                    help="Number of days back to search (GMT)")
parser.add_argument(metavar="file extension",
                    dest="file_extension",
                    choices=["7z", "apk", "bat", "bz", "bz2", "crypt", "dll", "doc", "docx", "exe", "gz", "hta", "iso", "jar", "json", "lnk", "ppt", "ps1", "py", "rar", "sfx", "sh", "tar", "vb", "vbs", "xld", "xls", "xlsx", "zip"],
                    help="7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip")
parser.add_argument("--timeout",
                    dest="timeout",
                    type=int,
                    default=30,
                    required=False,
                    help="Set time to wait for a connection")
parser.add_argument("--dryrun",
                    dest="dry_run",
                    action="store_true",
                    required=False,
                    help="Perform a test run to see what would be downloaded")
parser.add_argument("--exclude",
                    dest="exclude",
                    type=str,
                    default="",
                    required=False,
                    help="A comma-separated list of domains to not download content from (ex. 'google.com,bing.com')")
parser.add_argument("--tor",
                    dest="tor",
                    action="store_true",
                    required=False,
                    help="Download files over the Tor network")
args = parser.parse_args()

def main():
    """ """
    # Set variables for arguments
    qtype      = args.query_type.lower()
    delta      = args.delta
    ext        = args.file_extension.lower()
    exclusions = args.exclude.split(",")
    uagent     = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

    # Print start messages
    show_summary()
    show_network(uagent)

    # Read external.yaml
    with open("external.yaml", "r") as f:
        external = yaml.safe_load(f)

    if external["archives"] is not None:
        archives = external["archives"]
    else:
        print(colored("At least one extension is required for 'archives'.", "red", attrs=["bold"]))
        exit()

    if external["files"] is not None:
        files = external["files"]
    else:
        print(colored("At least one extension is required for 'files'.", "red", attrs=["bold"]))
        exit()

    # Set queries
    queries = external["queries"]

    # Build dict of extensions
    extensions = {}
    extensions.update(archives)
    extensions.update(files)
    
    # Request URLs from urlscan.io
    timeout = args.timeout
    urls    = get_urls(delta, queries, qtype, ext, uagent, timeout, extensions)

    for url in sorted(set(urls), key=urls.index):
        # Check if the current URL has already been redirected to
        if "redirect" in vars() and redirect == url:
            del redirect
            continue

        # Split URL into parts
        split_url   = url.split("/")
        protocol    = split_url[0]
        domain      = split_url[2]
        skip_domain = False
        
        # Skip exclusions
        for exclusion in exclusions:
            if domain == exclusion or domain.endswith(".{}".format(exclusion)):
                skip_domain = True
                break

        if skip_domain:
            print("[*] Skipping : {}".format(colored(url, "yellow")))
            continue

        print("[*] Original : {}".format(colored(url, "cyan")))
        url = "//".join([protocol, domain])

        # Build list of URL resources
        resources = split_url[3:]
        resources = ['/{}'.format(x) for x in resources]
        resources.insert(0, "")

        for resource in resources:
            # Combine current URL and resource
            url = "{}{}".format(url, resource)

            # Follow URL path and continue if a download was detected for a dry-run
            if "dry_domain" in vars():
                print("[*] Download : {} (Recursively downloaded)".format(
                    colored(url, "green", attrs=["underline", "bold"])
                ))
                continue

            # Send first request to the URL
            print("[*] Session  : {}".format(colored(url, "blue")))

            try:
                resp = requests.get(url,
                                    proxies=proxies,
                                    headers={"User-Agent": uagent},
                                    timeout=timeout,
                                    allow_redirects=True)
            except Exception as err:
                print("[!] Error    : {}".format(
                    colored(err, "red", attrs=["bold"])
                ))
                continue

            if resp.status_code != 200:
                continue

            # An open directory is found
            if "Index of " in resp.content:
                if glob.glob("./*/{}".format(domain.split(":")[0])):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red", attrs=["underline", "bold"]),
                        domain.split(":")[0]
                    ))
                    break

                for extension in extensions.keys():
                    if ".{}<".format(extension) in resp.content.lower() and extension in archives:
                        directory = "KitJackinSeason"
                    elif ".{}<".format(ext) in resp.content.lower() and extension in files:
                        directory = "InterestingFile"
                    else:
                        continue

                    print("[*] Download : {} ('Index of ' found)".format(
                        colored(url, "green")
                    ))

                    if args.dry_run:
                        dry_domain = True
                        break
            
                    try:
                        if directory == "InterestingFile":
                            os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))

                        subprocess.call([
                            "{}".format(torsocks),
                            "wget",
                            "--quiet",
                            "--execute=robots=off",
                            "--tries=2",
                            "--no-clobber",
                            "--timeout={}".format(timeout),
                            "--waitretry=0",
                            "--directory-prefix=./{}/{}".format(directory, domain.split(":")[0]),
                            "--content-disposition",
                            "--recursive",
                            "--level=0",
                            "--no-parent",
                            url
                        ])
                        print("[*] Complete : {}".format(
                            colored(url, "green", attrs=["underline", "bold"])
                        ))
                        break
                    except Exception as err:
                        print("[!] Error    : {}".format(
                            colored(err, "red", attrs=["bold"])
                        ))
                        continue

            # A URL is found ending in the specified extension but the server responded with no Content-Type
            if "Content-Type" not in resp.headers.keys():
                if os.path.exists("./InterestingFile/{}".format(domain.split(":")[0])):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red", attrs=["underline", "bold"]),
                        domain.split(":")[0]
                    ))
                    break

                if url.endswith('.{}'.format(ext)):
                    if resp.url != url:
                        redirect = resp.url
                        print("[*] Redirect : {} (Responded with no Content-Type)".format(
                            colored(redirect, "green")
                        ))
                    else:
                        print("[*] Download : {} (Responded with no Content-Type)".format(
                            colored(url, "green")
                        ))

                    if args.dry_run:
                        break

                    try:
                        os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))

                        subprocess.call([
                            "{}".format(torsocks),
                            "wget",
                            "--quiet",
                            "--execute=robots=off",
                            "--tries=2",
                            "--no-clobber",
                            "--timeout={}".format(timeout),
                            "--waitretry=0",
                            "--directory-prefix=./InterestingFile/{}".format(domain.split(":")[0]),
                            "--content-disposition",
                            "--no-parent",
                            url
                        ])
                        print("[*] Complete : {}".format(
                            colored(url, "green", attrs=["underline", "bold"])
                        ))
                        break
                    except Exception as err:
                        print("[!] Error    : {}".format(
                            colored(err, "red", attrs=["bold"])
                        ))
                        continue

            # A file is found with the Mime-Type of the specified extension
            if resp.headers["Content-Type"].startswith(extensions[ext]) or url.endswith(".{}".format(ext)):
                if os.path.exists("./InterestingFile/{}".format(domain.split(":")[0])):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red", attrs=["underline", "bold"]),
                        domain.split(":")[0]
                    ))
                    break

                if resp.url != url:
                    redirect = resp.url
                    print("[*] Redirect : {} ({} found)".format(
                        colored(redirect, "green"),
                        ext
                    ))
                else:
                    print("[*] Download : {} ({} found)".format(
                        colored(url, "green"),
                        ext
                    ))

                if args.dry_run:
                    break

                try:
                    os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))

                    subprocess.call([
                        "{}".format(torsocks),
                        "wget",
                        "--quiet",
                        "--execute=robots=off",
                        "--tries=2",
                        "--no-clobber",
                        "--timeout={}".format(timeout),
                        "--waitretry=0",
                        "--directory-prefix=./InterestingFile/{}".format(domain.split(":")[0]),
                        "--content-disposition",
                        "--no-parent",
                        url
                    ])
                    print("[*] Complete : {}".format(
                        colored(url, "green", attrs=["underline", "bold"])
                    ))
                    break
                except Exception as err:
                    print("[!] Error    : {}".format(
                        colored(err, "red", attrs=["bold"])
                    ))
                    continue

        if "dry_domain" in vars():
            del dry_domain
    return

def show_summary():
    """Print summary of arguments selected"""
    if args.dry_run:
        print(colored("Starting dry run...\n", "yellow", attrs=["bold"]))

    print("Summary:")
    print("    query_type     : {}".format(args.query_type.lower()))
    print("    delta          : {}".format(args.delta))
    print("    file_extension : {}".format(args.file_extension.lower()))
    print("    exclusions     : {}".format(args.exclude.split(",")))
    print("    timeout        : {}".format(args.timeout))
    print("    tor            : {}\n".format(args.tor))
    return

def show_network(uagent):
    """Select network to use, get IP address, and print message"""
    global torsocks
    global proxies
    if args.tor:
        ip_type  = "Tor"
        proxies  = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
        torsocks = "torsocks"
    else:
        ip_type  = "Original"
        proxies  = {}
        torsocks = ""

    try:
        requested_ip = requests.get("https://api.ipify.org",
                                     proxies=proxies,
                                     headers={"User-Agent": uagent},
                                     timeout=args.timeout,
                                     allow_redirects=True).content
    except Exception as err:
        print("[!] Error    : {}".format(
            colored(err, "red", attrs=["bold"])
        ))
        exit()

    print(colored("Getting IP Address...", "yellow", attrs=["bold"]))
    if args.tor:
        obfuscated_ip = ".".join(["XXX.XXX.XXX", requested_ip.split(".")[:-1][0]])
        print(colored("{} IP: {}\n".format(ip_type, obfuscated_ip), "yellow", attrs=["bold"]))
    else:
        print(colored("{} IP: {}\n".format(ip_type, requested_ip), "yellow", attrs=["bold"]))
    return

def get_urls(delta, queries, qtype, ext, uagent, timeout, extensions):
    """Request URLs from urlscan.io"""
    # Get stopping point
    today    = datetime.now()
    timespan = datetime.strftime(today - timedelta(delta), "%a, %d %b %Y 05:00:00")
    timespan = datetime.strptime(timespan, "%a, %d %b %Y %H:%M:%S")

    api  = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename%3A.{}&size=10000"
    resp = requests.get(api.format(queries[qtype], ext),
                        proxies=proxies,
                        headers={"User-Agent": uagent},
                        timeout=timeout,
                        allow_redirects=True)

    if not (resp.status_code == 200 and "results" in resp.json().keys()):
        exit()

    results = resp.json()["results"]
    urls    = []

    for result in results:
        # Break at delta specified
        analysis_time = datetime.strptime(result["task"]["time"], "%Y-%m-%dT%H:%M:%S.%fZ")

        if analysis_time < timespan:
            break

        # Build list of URLs ending with specified extension or Mime-Type
        url = result["page"]["url"]

        if url.endswith('.{}'.format(ext)):
            urls.append(url)
            continue
    
        if "files" in result.keys():
            result_files = [x for x in result["files"] if x["mimeType"].startswith(extensions[ext])]

            if len(result_files) > 0:
                urls.append(url)
    return urls

if __name__ == "__main__":    
    main()
