#!/usr/bin/python
"""
Description:
- Download a list of newly registered domains from WHOIS Domain Search (whoisds.com)
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

1 positional argument needed:
- Delta : Number of days back to search (GMT)

Optional arguments:
- --file-dir : Directory to use for interesting files detected (default: ./InterestingFiles/)
- --kit-dir  : Directory to use for phishing kits detected (default: ./KitJackinSeason/)
- --log-nc   : File to store domains that have not been checked
- --quiet    : Don't show wget output
- --timeout  : Set time to wait for a connection
- --tor      : Download files via the Tor network
- --verbose  : Show error messages

Credit: https://github.com/x0rz/phishing_catcher

Resources:
    https://whoisds.com/newly-registered-domains
    http://docs.python-requests.org/en/master/user/advanced/#proxies
    https://gist.github.com/jefftriplett/9748036
    https://ec.haxx.se/libcurl-proxies.html
    https://trac.torproject.org/projects/tor/wiki/doc/torsocks

Usage:

```
python opendir_whoisds.py <DELTA> [--file-dir] [--kit-dir] [--log-nc] [--quiet] [--timeout] [--tor] [--verbose]
```

Debugger: open("/tmp/opendir.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
import base64
import datetime
import os
import Queue
import re
import sys
import threading
import time
import zipfile

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import entropy
from Levenshtein import distance
import requests
import subprocess
from termcolor import colored, cprint
from tld import get_tld
import tqdm
import yaml

from confusables import unconfuse


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories via Certstream.")
parser.add_argument(dest="delta",
                    type=int,
                    help="Number of days back to search (GMT)")
parser.add_argument("--file-dir",
                    dest="fdir",
                    default="./InterestingFile/",
                    required=False,
                    help="Directory to use for interesting files detected (default: ./InterestingFiles/)")
parser.add_argument("--kit-dir",
                    dest="kdir",
                    default="./KitJackinSeason/",
                    required=False,
                    help="Directory to use for phishing kits detected (default: ./KitJackinSeason/)")
parser.add_argument("--log-nc",
                    dest="log_nc",
                    default="None",
                    required=False,
                    type=str,
                    help="File to store domains that have not been checked")
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
    global uagent
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    global timeout
    timeout = args.timeout

    global quiet
    if args.quiet:
        quiet = "--quiet"

    # Print start messages
    show_summary()
    show_network(uagent, timeout)
    domains = get_domains()
    rd_count = len(domains)

    # Read suspicious.yaml and external.yaml
    with open("suspicious.yaml", "r") as f:
        global suspicious
        suspicious = yaml.safe_load(f)

    with open("external.yaml", "r") as f:
        external = yaml.safe_load(f)

    if external["override_suspicious.yaml"] is True:
        suspicious = external

        for key in external.keys():
            if external[key] is None:
                external_error(key, "external")

            suspicious[key] = external[key]
    else:
        for key in external.keys():
            if key == "override_suspicious.yaml" or key == "queries":
                continue

            if key == "keywords" or key == "tlds":
                if external[key] is not None:
                    suspicious[key].update(external[key])
            elif key == "archives" or key == "files":
                if external[key] is not None:
                    suspicious[key] = external[key]
                else:
                    external_error(key, "external")

            if key not in suspicious.keys() or suspicious[key] is None:
                external_error(key, "suspicious")

    print(colored("Scoring {} domains...\n".format(rd_count), "yellow", attrs=["bold"]))
    global pbar
    pbar = tqdm.tqdm(desc="domain_update", unit="domain")
    suspicious_domains = return_suspicious(domains)
    sd_count = len(suspicious_domains)

    print(colored("\n\nChecking {} suspicious domains...\n".format(sd_count), "yellow", attrs=["bold"]))
    for suspicious_domain in suspicious_domains:
        url = "http://{}".format(suspicious_domain)
        check_url(url)
    return

def show_summary():
    """Print summary of arguments selected"""

    print("Summary:")
    print("    file_dir : {}".format(args.fdir))
    print("    kit_dir  : {}".format(args.kdir))
    print("    log_file : {}".format(args.log_nc))
    print("    quiet    : {}".format(args.quiet))
    print("    timeout  : {}".format(args.timeout))
    print("    tor      : {}".format(args.tor))
    print("    verbose  : {}\n".format(args.verbose))
    return

def show_network(uagent, timeout):
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
        global requested_ip
        requested_ip = requests.get("https://api.ipify.org",
                                     proxies=proxies,
                                     headers={"User-Agent": uagent},
                                     timeout=timeout,
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

def get_domains():
    """ """
    now       = datetime.datetime.now()
    global yesterday
    yesterday = datetime.datetime.strftime(now - datetime.timedelta(args.delta), "%Y-%m-%d")
    filename  = "{}.zip".format(yesterday)
    encoded_filename = base64.b64encode(filename)
    whoisds = "https://whoisds.com//whois-database/newly-registered-domains/{}/nrd"

    try:
        print(colored("Attempting to get domain list using encoded filename...", "yellow", attrs=["bold"]))
        resp = requests.get(whoisds.format(encoded_filename))
    except Exception as err:
        if args.verbose:
            print("[!] Error    : {}".format(
                colored(err, "red", attrs=["bold", "underline"])
            ))

        print("[!] Failed   : {}".format(
            colored("Use --verbose to capture the error message", "red", attrs=["underline"])
        ))

        try:
            print(colored("Attempting to get domain list using plain-text filename...", "yellow", attrs=["bold"]))
            resp = requests.get(whoisds.format(filename))
        except Exception as err:
            if args.verbose:
                print("[!] Error    : {}".format(
                    colored(err, "red", attrs=["bold", "underline"])
                ))

            print("[!] Failed   : {}".format(
                colored("Use --verbose to capture the error message", "red", attrs=["underline"])
            ))
            exit()

    try:
        if resp.status_code == 200 and filename in resp.headers["Content-Disposition"]:
            print(colored("Download successful...\n", "yellow", attrs=["bold"]))

            content_disposition = resp.headers["Content-Disposition"].replace("attachment; filename=", "")
            content_disposition = content_disposition.replace('"', "")
            old_name = "{}{}".format(args.kdir, content_disposition)
            domain_file = content_disposition.replace(".zip", ".txt")
            new_name = "{}{}".format(args.kdir, domain_file)

            with open(old_name, "wb") as cd:
                cd.write(resp.content)

            compressed_file = zipfile.ZipFile(old_name).namelist()[0]
            zipfile.ZipFile(old_name).extractall(args.kdir)
            os.rename("{}{}".format(args.kdir, compressed_file), new_name)
        else:
            raise ValueError("Newly registered domains file was not downloaded successfully.")
    except Exception as err:
        if args.verbose:
            print("[!] Error    : {}".format(
                colored(err, "red", attrs=["bold", "underline"])
            ))

        print("[!] Failed   : {}".format(
            colored("Use --verbose to capture the error message", "red", attrs=["underline"])
        ))
        exit()

    with open(new_name, "r") as open_df:
        domains = open_df.read().splitlines()
    return domains

def return_suspicious(domains):
    """ """
    suspicious_domains = []

    for domain in domains:
        pbar.update(1)

        if domain.startswith("*."):
            continue

        score = score_domain(domain.lower())
        
        if score < 75 or \
                domain.startswith("www.") or \
                domain.startswith("STH-for-Google ") or \
                domain.endswith("chat.kowari.macmoney.co.za") or \
                domain.endswith("facebook.sitechs.net") or \
                domain.endswith(".composedb.com") or \
                domain.endswith(".brilliantpocket.com") or \
                domain.endswith(".google.com") or \
                domain.endswith(".microsoft.com") or \
                domain.endswith(".netflix.com") or \
                domain.endswith(".playapps.download") or \
                domain.endswith(".windows.net"):
            if not args.log_nc == "None":
                with open(args.log_nc, "a") as log_nc:
                    log_nc.write("{}\n".format(domain))
            continue

        if score >= 120:
            tqdm.tqdm.write(
                "[!] Suspicious: "
                "{} (score={})".format(colored(domain, "red", attrs=["underline", "bold"]), score))
        elif score >= 90:
            tqdm.tqdm.write(
                "[!] Suspicious: "
                "{} (score={})".format(colored(domain, "yellow", attrs=["underline"]), score))
        elif score >= 75:
            tqdm.tqdm.write(
                "[!] Likely    : "
                "{} (score={})".format(colored(domain, "cyan", attrs=["underline"]), score))

        suspicious_domains.append(domain)
    return suspicious_domains

def score_domain(domain):
    """ """
    score = 0
    for t in suspicious["tlds"]:
        if domain.endswith(t):
            score += 20

    if domain.startswith("*."):
        domain = domain[2:]

    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)

        if res is not None:
            domain = '.'.join([res.subdomain, res.domain])
    except Exception as err:
        if args.verbose:
            print("[!] Error    : {}".format(
                colored(err, "red", attrs=["bold", "underline"])))

        print("[!] Failed   : {}".format(
            colored(domain, "red", attrs=["underline"])))
        pass

    score += int(round(entropy.shannon_entropy(domain)*50))

    domain = unconfuse(domain)

    words_in_domain = re.split(r"\W+", domain)

    if domain.startswith("*."):
        domain = domain[2:]
        if words_in_domain[0] in ["com", "net", "org"]:
            score += 10

    for word in suspicious["keywords"]:
        if word in domain:
            score += suspicious["keywords"][word]

    for key in [k for (k,s) in suspicious["keywords"].items() if s >= 70]:
        for word in [w for w in words_in_domain if w not in ["email", "mail", "cloud"]]:
            if distance(str(word), str(key)) == 1:
                score += 70

    if "xn--" not in domain and domain.count("-") >= 4:
        score += domain.count("-") * 3

    if domain.count(".") >= 3:
        score += domain.count(".") * 3

    return score

def check_url(url):
    """ """
    print("[*] Session   : {}".format(colored(url, "blue")))
    try:
        resp = requests.get(url,
                            proxies=proxies,
                            headers={"User-Agent": uagent},
                            timeout=timeout,
                            allow_redirects=True)
    except Exception as err:
        if args.verbose:
            print("[!] Error     : {}".format(
                    colored(err, "red", attrs=["bold", "underline"])))

        print("[!] Failed    : {}".format(
                colored(url, "red", attrs=["underline"])))
        return

    if not (resp.status_code == 200 and "Index of " in resp.content):
        return

    extensions = suspicious["archives"].keys() + suspicious["files"].keys()

    for ext in extensions:
        if "{}<".format(ext) in resp.content.lower() and ext in suspicious["archives"]:
            directory = args.kdir

            if args.kdir:
                directory = args.kdir
        elif "{}<".format(ext) in resp.content.lower() and ext in suspicious["files"]:
            directory = args.fdir

            if args.fdir:
                directory = args.fdir
        else:
            continue

        if not directory.endswith("/"):
            directory = "{}/".format(directory)

        directory = "{}{}".format(directory, yesterday)

        print("[*] Download  : {} ('Index of ' found)".format(
                colored(url, "green", attrs=["bold"])))

        try:
            wget_command = format_wget(timeout, directory, uagent, url)

            subprocess.call(wget_command)

            print("[*] Complete  : {}".format(
                    colored(url, "green", attrs=["bold", "underline"])))
            break
        except Exception as err:
            if args.verbose:
                print("[!] Error     : {}".format(
                        colored(err, "red", attrs=["bold", "underline"])))

            print("[!] Failed    : {}".format(
                    colored(url, "red", attrs=["underline"])))
            continue  
    return

def external_error(key, override):
    """ """
    print(colored(
        "No {} found in {}.yaml ({}:).".format(key, override, key),
        "red",
        attrs=["bold"]
    ))
    exit()

def format_wget(timeout, directory, uagent, url):
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
        "--no-check-certificate",
        "--recursive",
        "--level=0",
        "--no-parent"
    ]

    if torsocks != None:
        wget_command.insert(0, torsocks)

    if args.quiet:
        wget_command.append(quiet)

    wget_command.append(url)
        
    return wget_command

if __name__ == "__main__":
    main()
