#!/opt/splunk/bin/python
"""
Description:
- Stream CT logs via Certstream
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

Credit: https://github.com/x0rz/phishing_catcher

Usage:

```
python opendir_certstream.py
```

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

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


certstream_url = "wss://certstream.calidog.io"
pbar           = tqdm.tqdm(desc="certificate_update", unit="cert")
uagent         = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

global url_queue
url_queue = Queue.Queue()

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
                url   = url_queue.get()
                tqdm.tqdm.write(
                    "[*] Session   : "
                    "{}".format(colored(url, "blue")))
                try:
                    resp = requests.get(url, headers={"User-Agent": uagent}, timeout=3.1)
                except:
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
                        "{}".format(colored(url, "green", attrs=["underline", "bold"])))

                    try:
                        subprocess.call([
                            "wget",
                            "--execute=robots=off",
                            "--tries=2",
                            "--no-clobber",
                            "--timeout=3.1",
                            "--waitretry=0",
                            "--directory-prefix=./{}/".format(directory),
                            "--content-disposition",
                            "--recursive",
                            "--level=0",
                            "--no-parent",
                            url
                        ])
                        exit(0)
                        break
                    except:
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
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
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

if __name__ == "__main__":
    with open("suspicious.yaml", "r") as f:
        suspicious = yaml.safe_load(f)

    with open("external.yaml", "r") as f:
        external = yaml.safe_load(f)

    if external["override_suspicious.yaml"] is True:
        suspicious = external
    else:
        if external["keywords"] is not None:
            suspicious["keywords"].update(external["keywords"])

        if external["tlds"] is not None:
            suspicious["tlds"].update(external["tlds"])

        if external["archives"] is not None:
            suspicious["archives"] = external["archives"]
        else:
            print(colored("At least one extension is required for 'archives'.", "red", attrs=["bold"]))
            exit()

        if external["files"] is not None:
            suspicious["files"] = external["files"]
        else:
            print(colored("At least one extension is required for 'files'.", "red", attrs=["bold"]))
            exit()

    QueueManager()
    certstream.listen_for_events(callback, url=certstream_url)
