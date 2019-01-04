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
- --level    : Recursion depth (default=1, infinite=0)
- --log-nc   : File to store domains that have not been checked
- --quiet    : Don't show wget output
- --threads  : Numbers of threads to spawn
- --timeout  : Set time to wait for a connection
- --tor      : Download files via the Tor network
- --verbose  : Show error messages

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
import zipfile

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from termcolor import colored, cprint

import commons


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories via Certstream.")
parser.add_argument(dest="delta",
                    type=int,
                    help="Number of days back to search (GMT)")
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

def get_domains(day):
    """ """
    # Set globals
    global old_name
    global new_name

    filename = "{}.zip".format(day)
    encoded_filename = base64.b64encode(filename)
    whoisds = "https://whoisds.com//whois-database/newly-registered-domains/{}/nrd"

    try:
        print(colored("Attempting to get domain list using encoded filename...", "yellow", attrs=["bold"]))
        resp = requests.get(whoisds.format(encoded_filename))
    except Exception as err:
        commons.failed_message(args, err, None)

        try:
            print(colored("Attempting to get domain list using plain-text filename...", "yellow", attrs=["bold"]))
            resp = requests.get(whoisds.format(filename))
        except Exception as err:
            commons.failed_message(args, err, None)
            exit()

    try:
        if resp.status_code == 200 and filename in resp.headers["Content-Disposition"]:
            print(colored("Download successful...\n", "yellow", attrs=["bold"]))

            content_disposition = resp.headers["Content-Disposition"].replace("attachment; filename=", "")
            content_disposition = content_disposition.replace('"', "")
            old_name = "{}{}".format(args.kit_dir, content_disposition)
            new_name = old_name.replace(".zip", ".txt")

            with open(old_name, "wb") as cd:
                cd.write(resp.content)

            compressed_file = zipfile.ZipFile(old_name).namelist()[0]
            zipfile.ZipFile(old_name).extractall(args.kit_dir)
            os.rename("{}{}".format(args.kit_dir, compressed_file), new_name)
        else:
            raise ValueError("Newly registered domains file was not downloaded successfully.")
    except Exception as err:
        commons.failed_message(args, err, None)
        exit()

    with open(new_name, "r") as open_df:
        domains = open_df.read().splitlines()
    return domains

def main():
    """ """
    # Create globals
    global domain_queue
    global url_queue
    global proxies
    global torsocks
    global suspicious
    global exclusions

    # Print start messages
    commons.show_summary(args)
    proxies, torsocks = commons.show_network(args, uagent)

    # Get dates
    now = datetime.datetime.now()
    day = datetime.datetime.strftime(now - datetime.timedelta(args.delta), "%Y-%m-%d")

    # Get list of domains
    domains = get_domains(day)

    # Read suspicious.yaml and external.yaml
    suspicious = commons.read_externals()

    # Recompile exclusions
    if "exclusions" in suspicious.keys():
        exclusions = commons.recompile_exclusions(suspicious["exclusions"])
    else:
        exclusions = []

    # Create queues
    print(colored("Starting the queues...\n", "yellow", attrs=["bold"]))
    domain_queue = Queue.Queue()
    url_queue    = Queue.Queue()
    commons.DomainQueueManager(args, domain_queue, suspicious, exclusions, url_queue)
    commons.UrlQueueManager(args, url_queue, proxies, uagent, suspicious, day, torsocks)

    print(colored("Scoring and checking the domains...\n", "yellow", attrs=["bold"]))
    for domain in domains:
        domain_queue.put(domain)

    domain_queue.join()
    url_queue.join()

    os.remove(old_name)
    os.remove(new_name)
    return

if __name__ == "__main__":
    main()
