#!/usr/bin/python
"""
Description:
- Stream CT logs via Certstream
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

Optional arguments:
- --file-dir : Directory to use for interesting files detected (default: ./InterestingFiles/)
- --kit-dir  : Directory to use for phishing kits detected (default: ./KitJackinSeason/)
- --level    : Recursion depth (default=1, infinite=0)
- --log-nc   : File to store domains that have not been checked
- --quiet    : Don't show wget output
- --threads  : Numbers of threads to spawn
- --timeout  : Set time to wait for a connection
- --tor      : Download files via the Tor network
- --verbose  : Show error messages

Usage:

```
python opendir_certstream.py [--file-dir] [--kit-dir] [--log-nc] [--quiet] [--timeout] [--tor] [--verbose]
```

Debugger: open("/tmp/opendir.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
from datetime import date
import os
import Queue
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import certstream
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import subprocess
from termcolor import colored, cprint
import tqdm

import commons


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories via Certstream.")
parser.add_argument("--file-dir",
                    dest="file_dir",
                    default="./InterestingFile/",
                    required=False,
                    help="Directory to use for interesting files detected (default: ./InterestingFiles/)")
parser.add_argument("--kit-dir",
                    dest="kit_dir",
                    default="./KitJackinSeason/",
                    required=False,
                    help="Directory to use for phishing kits detected (default: ./KitJackinSeason/)")
parser.add_argument("--level",
                    dest="level",
                    default=1,
                    required=False,
                    type=str,
                    help="Directory depth (default=1, infinite=0")
parser.add_argument("--log-nc",
                    dest="log_nc",
                    required=False,
                    type=str,
                    help="File to store domains that have not been checked")
parser.add_argument("--quiet",
                    dest="quiet",
                    action="store_true",
                    required=False,
                    help="Don't show wget output")
parser.add_argument("--threads",
                    dest="threads",
                    default=3,
                    required=False,
                    type=int,
                    help="Numbers of threads to spawn")
parser.add_argument("--timeout",
                    dest="timeout",
                    default=30,
                    required=False,
                    type=int,
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
args   = parser.parse_args()
uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

# Fix directory names
args = commons.fix_directory(args)

def callback(message, context):
    """Callback handler for certstream events."""
    if message["message_type"] == "heartbeat":
        return

    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]

        for domain in all_domains:
            pbar.update(1)

            if domain.startswith("*."):
                continue

            score = commons.score_domain(suspicious, domain.lower(), args)

            if "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
                score += 10

            match_found = False
            for exclusion in exclusions:
                if exclusion.match(domain):
                    match_found = True
                    break
            
            if match_found:
                continue
            
            if score < 75:
                if args.log_nc:
                    with open(args.log_nc, "a") as log_nc:
                        log_nc.write("{}\n".format(domain))
                continue

            if score >= 120:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, "red", attrs=["underline", "bold"]), score))
            elif score >= 90:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, "yellow", attrs=["underline"]), score))
            elif score >= 75:
                tqdm.tqdm.write("[!] Likely    : {} (score={})".format(colored(domain, "cyan", attrs=["underline"]), score))

            url = "https://{}".format(domain)

            if not url in list(url_queue.queue):
                url_queue.put(url)

                with open("queue_file.txt", "a") as qfile:
                    qfile.write("{}\n".format(url))

def main():
    """ """
    # Create globals
    global url_queue
    global proxies
    global torsocks
    global suspicious
    global exclusions
    global pbar

    # Print start messages
    commons.show_summary(args)
    proxies, torsocks = commons.show_network(args, uagent)

    # Get today's date
    day = date.today()

    # Read suspicious.yaml and external.yaml
    suspicious = commons.read_externals()

    # Recompile exclusions
    if "exclusions" in suspicious.keys():
        exclusions = commons.recompile_exclusions(suspicious["exclusions"])
    else:
        exclusions = []

    # Start queue and listen for events via Certstream
    if not (os.path.exists(args.kit_dir) or os.path.exists(args.file_dir)):
        print(colored("Either the file or kit directory is temporarily unavailable. Exiting!", "red", attrs=["underline"]))
        exit()

    # Create queues
    print(colored("Starting queue...\n", "yellow", attrs=["bold"]))
    url_queue = Queue.Queue()
    commons.UrlQueueManager(args, url_queue, proxies, uagent, suspicious, day, torsocks)

    try:
        print(colored("Attempting to reload the previous queue...\n", "yellow", attrs=["bold"]))
        with open("queue_file.txt", "r") as qfile:
            for url in qfile.read().splitlines():
                url_queue.put(url)
    except Exception as err:
        commons.failed_message(args, err, None)

    print(colored("Connecting to Certstream...\n", "yellow", attrs=["bold"]))
    pbar = tqdm.tqdm(desc="certificate_update", unit="cert")
    certstream.listen_for_events(callback, url="wss://certstream.calidog.io")

if __name__ == "__main__":
    main()
