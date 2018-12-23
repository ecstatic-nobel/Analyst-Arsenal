#!/usr/bin/python
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
- --quiet   : Don't show wget output
- --timeout : Set time to wait for a connection
- --tor     : Download files via the Tor network
- --verbose : Show error messages

Credit: https://github.com/ninoseki/miteru

Resources:
    http://docs.python-requests.org/en/master/user/advanced/#proxies
    https://gist.github.com/jefftriplett/9748036
    https://ec.haxx.se/libcurl-proxies.html

Usage:

```
python opendir_urlscan.py <QUERY_TYPE> <DELTA> <FILE_EXTENSION> [--dry-run] [--exclude=CSV] [--quiet] [--timeout] [--tor] [--verbose]
```

Debugger: open("/tmp/opendir.txt", "a").write("{}: <MSG>\n".format(<VAR>))
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
parser.add_argument("--file-dir",
                    dest="fdir",
                    default="./InterestingFile/",
                    required=False,
                    help="Directory to use for interesting files detected (default: ./InterestingFiles))")
parser.add_argument("--kit-dir",
                    dest="kdir",
                    default="./KitJackinSeason/",
                    required=False,
                    help="Directory to use for phishing kits detected (default: ./KitJackinSeason))")
parser.add_argument("--quiet",
                    dest="quiet",
                    action="store_true",
                    required=False,
                    help="Don't show wget output")
parser.add_argument("--timeout",
                    dest="timeout",
                    type=int,
                    default=30,
                    required=False,
                    help="Set time to wait for a connection")
parser.add_argument("--tor",
                    dest="tor",
                    action="store_true",
                    required=False,
                    help="Download files over the Tor network")
parser.add_argument("--verbose",
                    dest="verbose",
                    action="store_true",
                    required=False,
                    help="Show error messages")
args = parser.parse_args()

def main():
    """ """
    # Set variables for arguments
    qtype      = args.query_type.lower()
    delta      = args.delta
    ext        = args.file_extension.lower()
    exclusions = args.exclude.split(",")
    uagent     = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

    global quiet
    if args.quiet:
        quiet = "--quiet"

    # Print start messages
    show_summary()
    show_network(uagent)

    # Read external.yaml
    with open("external.yaml", "r") as f:
        external = yaml.safe_load(f)

    for key in external.keys():
        if key == "override_suspicious.yaml" or key == "keywords" or key == "tlds":
            continue

        if external[key] is not None and (key == "archives" or key == "files" or key == "queries"):
            if key == "archives":
                archives = external[key]
            elif key == "files":
                files = external[key]
            elif key == "queries":
                queries = external[key]
        else:
            print(colored(
                "No {} found in external.yaml ({}:).".format(key, key),
                "red",
                attrs=["bold"]
            ))
            exit()

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
        domain      = split_url[2].split(":")[0]
        skip_domain = False
        
        # Skip exclusions
        for exclusion in exclusions:
            if domain == exclusion or domain.endswith(".{}".format(exclusion)):
                skip_domain = True
                break

        if skip_domain:
            print("[*] Excluded : {}".format(colored(url, "red")))
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
                    colored(url, "green", attrs=["bold"])
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
                exception_message(err, url)
                continue

            if resp.status_code != 200:
                continue

            # An open directory is found
            if "Index of " in resp.content:
                if glob.glob("./*/{}".format(domain)):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red"),
                        domain
                    ))
                    break

                for extension in extensions.keys():
                    if ".{}<".format(extension) in resp.content.lower() and extension in archives:
                        directory = args.kdir
                        recursive = True
                    elif ".{}<".format(ext) in resp.content.lower() and extension in files:
                        directory = args.fdir
                        recursive = False
                    else:
                        continue

                    if not directory.endswith("/"):
                        directory = "{}/".format(directory)

                    print("[*] Download : {} ('Index of ' found)".format(
                        colored(url, "green", attrs=["bold"])
                    ))

                    if args.dry_run:
                        dry_domain = True
                        break
            
                    try:
                        if directory == args.fdir:
                            os.mkdir("{}{}".format(directory, domain))

                        wget_command = format_wget(timeout,
                                                   directory,
                                                   uagent,
                                                   recursive,
                                                   url)

                        subprocess.call(wget_command)

                        print("[*] Complete : {}".format(
                            colored(url, "green", attrs=["bold", "underline"])
                        ))
                        break
                    except Exception as err:
                        exception_message(err, url)
                        continue

            # A URL is found ending in the specified extension but the server responded with no Content-Type
            if "Content-Type" not in resp.headers.keys():
                directory = args.fdir
                recursive = False

                if not directory.endswith("/"):
                    directory = "{}/".format(directory)

                if os.path.exists("{}{}".format(directory, domain)):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red"),
                        domain
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
                            colored(url, "green", attrs=["bold"])
                        ))

                    if args.dry_run:
                        break

                    try:
                        os.mkdir("{}{}".format(directory, domain))

                        wget_command = format_wget(timeout,
                                                   directory,
                                                   uagent,
                                                   recursive,
                                                   url)

                        subprocess.call(wget_command)

                        print("[*] Complete : {}".format(
                            colored(url, "green", attrs=["bold", "underline"])
                        ))
                        break
                    except Exception as err:
                        exception_message(err, url)
                        continue

            # A file is found with the Mime-Type of the specified extension
            if resp.headers["Content-Type"].startswith(extensions[ext]) or url.endswith(".{}".format(ext)):
                directory = args.fdir
                recursive = False

                if not directory.endswith("/"):
                    directory = "{}/".format(directory)

                if os.path.exists("{}{}".format(directory, domain)):
                    print("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red"),
                        domain
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
                        colored(url, "green", attrs=["bold"]),
                        ext
                    ))

                if args.dry_run:
                    break

                try:
                    os.mkdir("{}{}".format(directory, domain))

                    wget_command = format_wget(timeout,
                                               directory,
                                               uagent,
                                               recursive,
                                               url)
                    
                    subprocess.call(wget_command)

                    print("[*] Complete : {}".format(
                        colored(url, "green", attrs=["bold", "underline"])
                    ))
                    break
                except Exception as err:
                    exception_message(err, url)
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
    print("    exclusions     : {}".format(args.exclude.split(",")))
    print("    file_dir       : {}".format(args.fdir))
    print("    file_extension : {}".format(args.file_extension.lower()))
    print("    kit_dir        : {}".format(args.kdir))
    print("    quiet          : {}".format(args.quiet))
    print("    timeout        : {}".format(args.timeout))
    print("    tor            : {}".format(args.tor))
    print("    verbose        : {}\n".format(args.verbose))
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
        torsocks = None

    try:
        requested_ip = requests.get("https://api.ipify.org",
                                     proxies=proxies,
                                     headers={"User-Agent": uagent},
                                     timeout=args.timeout,
                                     allow_redirects=True).content
    except Exception as err:
        if args.verbose:
            print("[!] Error    : {}".format(
                colored(err, "red", attrs=["bold", "underline"])
            ))

        print("[!] Failed   : {}".format(
            colored("Use --verbose to capture the error message", "red", attrs=["underline"])
        ))
        exit()

    print(colored("Getting IP Address...", "yellow", attrs=["bold"]))

    if args.tor:
        obfuscated_ip = ".".join(["XXX.XXX.XXX", requested_ip.split(".")[:-1][0]])
        print(colored("{} IP: {}\n".format(ip_type, obfuscated_ip), "yellow", attrs=["bold"]))
    else:
        print(colored("{} IP: {}\n".format(ip_type, requested_ip), "yellow", attrs=["bold"]))
    return

def exception_message(err, url):
    """ """
    if args.verbose:
        print("[!] Error    : {}".format(
            colored(err, "red", attrs=["bold", "underline"])
        ))

    print("[!] Failed   : {}".format(
        colored(url, "red", attrs=["underline"])
    ))
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

def format_wget(timeout, directory, uagent, recursive, url):
    """Return the wget command needed to download files."""

    wget_command = [
        "wget",
        "--execute=robots=off",
        "--tries=2",
        "--no-clobber",
        "--timeout={}".format(timeout),
        "--waitretry=0",
        "--directory-prefix={}".format(directory),
        "--header='User-Agent: {}'".format(uagent),
        "--content-disposition",
        "--no-parent"
    ]

    if torsocks != None:
        wget_command.insert(0, torsocks)

    if args.quiet:
        wget_command.append(quiet)

    if recursive == False:
        wget_command.append("--recursive")
        wget_command.append("--level=0")

    wget_command.append(url)
        
    return wget_command

if __name__ == "__main__":    
    main()
