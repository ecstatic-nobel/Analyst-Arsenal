#!/usr/bin/python
"""
Description:
- Stream CT logs via Certstream
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

Optional arguments:
- --quiet   : Don't show wget output
- --timeout : Set time to wait for a connection
- --tor     : Download files via the Tor network
- --verbose : Show error messages

Credit: https://github.com/x0rz/phishing_catcher

Resources:
    http://docs.python-requests.org/en/master/user/advanced/#proxies
    https://gist.github.com/jefftriplett/9748036
    https://ec.haxx.se/libcurl-proxies.html

Usage:

```
python opendir_certstream.py
```

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
import os
import Queue
import re
import sys
import threading
import time

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import certstream
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

# hxxp://sebastiandahlgren[.]se/2014/06/27/running-a-method-as-a-background-thread-in-python/
class QueueManager(object):
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, interval=1):
        """ Constructor
        :type interval: int
        :param interval: Check interval, in seconds
        """
        self.interval = interval

        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        """Process items in the queue."""
        while True:
            if url_queue.empty():
                time.sleep(self.interval)
                continue

            while not url_queue.empty():
                url = url_queue.get()

                tqdm.tqdm.write(
                    "[*] Session   : "
                    "{}".format(colored(url, "blue"))
                )
                try:
                    resp = requests.get(url,
                                        proxies=proxies,
                                        headers={"User-Agent": uagent},
                                        timeout=timeout,
                                        allow_redirects=True)
                except Exception as err:
                    if args.verbose:
                        tqdm.tqdm.write(
                            "[!] Error     : "
                            "{}".format(
                                colored(err, "red", attrs=["bold", "underline"])
                            )
                        )

                    tqdm.tqdm.write(
                        "[!] Failed    : "
                        "{}".format(
                            colored(url, "red", attrs=["underline"])
                        )
                    )
                    continue

                if not (resp.status_code == 200 and "Index of " in resp.content):
                    continue

                extensions = suspicious["archives"].keys() + suspicious["files"].keys()

                for ext in extensions:
                    if "{}<".format(ext) in resp.content.lower() and ext in suspicious["archives"]:
                        directory = "KitJackinSeason"
                    elif "{}<".format(ext) in resp.content.lower() and ext in suspicious["files"]:
                        directory = "InterestingFile"
                    else:
                        continue

                    tqdm.tqdm.write(
                        "[*] Download  : "
                        "{} ('Index of ' found)".format(
                            colored(url, "green", attrs=["bold"])
                        )
                    )

                    try:
                        wget_command = format_wget(timeout, directory, uagent, url)

                        subprocess.call(wget_command)

                        tqdm.tqdm.write(
                            "[*] Complete  : "
                            "{}".format(
                                colored(url, "green", attrs=["bold", "underline"])
                            )
                        )
                        break
                    except Exception as err:
                        if args.verbose:
                            tqdm.tqdm.write(
                                "[!] Error     : "
                                "{}".format(
                                    colored(err, "red", attrs=["bold", "underline"])
                                )
                            )

                        tqdm.tqdm.write(
                            "[!] Failed    : "
                            "{}".format(
                                colored(url, "red", attrs=["underline"])
                            )
                        )
                        continue
            time.sleep(self.interval)        

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

            score = score_domain(domain.lower())

            if "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
                score += 10
            
            if score < 75 or \
                 domain.startswith("www.") or \
                 domain == "chat.kowari.macmoney.co.za" or \
                 domain.endswith(".composedb.com") or \
                 domain.endswith(".brilliantpocket.com") or \
                 domain.endswith(".google.com") or \
                 domain.endswith(".microsoft.com") or \
                 domain.endswith(".netflix.com") or \
                 domain.endswith(".playapps.download") or \
                 domain.endswith(".windows.net"):
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

            url = "https://{}".format(domain)
            url_queue.put(url)

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
            tqdm.tqdm.write(
                "[!] Error    : "
                "{}".format(colored(err, "red", attrs=["bold", "underline"]))
            )

        tqdm.tqdm.write(
            "[!] Failed   : "
            "{}".format(colored(domain, "red", attrs=["underline"]))
        )
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

def main():
    """ """
    # Set variables for arguments
    global uagent
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    global timeout
    timeout = args.timeout
    certstream_url = "wss://certstream.calidog.io"
    global url_queue
    url_queue = Queue.Queue()

    global quiet
    if args.quiet:
        quiet = "--quiet"

    # Print start messages
    show_summary()
    show_network(uagent, timeout)

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

    # Start queue and listen for events via Certstream
    print(colored("Starting queue...\n", "yellow", attrs=["bold"]))
    QueueManager()

    global pbar
    pbar = tqdm.tqdm(desc="certificate_update", unit="cert")
    certstream.listen_for_events(callback, url=certstream_url)

def show_summary():
    """Print summary of arguments selected"""

    print("Summary:")
    print("    quiet   : {}".format(args.quiet))
    print("    timeout : {}".format(args.timeout))
    print("    tor     : {}".format(args.tor))
    print("    verbose : {}\n".format(args.verbose))
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
        "--directory-prefix=./{}/".format(directory),
        "--header='User-Agent: {}'".format(uagent),
        "--content-disposition",
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
