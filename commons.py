#!/usr/bin/python
"""

"""

import os
import re
import subprocess
import sys
import threading
import time

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import entropy
from Levenshtein import distance
import requests
from termcolor import colored, cprint
from tld import get_tld
import tqdm
import yaml

from confusables import unconfuse


# hxxp://sebastiandahlgren[.]se/2014/06/27/running-a-method-as-a-background-thread-in-python/
class DomainQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, domain_queue, suspicious, exclusions, url_queue):
        """ """
        self.args         = args
        self.domain_queue = domain_queue
        self.suspicious   = suspicious
        self.exclusions   = exclusions
        self.url_queue    = url_queue

        for thread in range(self.args.threads):
            worker = threading.Thread(target=self.return_suspicious)
            worker.daemon = True
            worker.start()

    def return_suspicious(self):
        """ """
        while True:
            domain = self.domain_queue.get()
            score  = score_domain(self.suspicious, domain.lower(), self.args)

            for exclusion in self.exclusions:
                if exclusion.match(domain):
                    self.domain_queue.task_done()
                    continue
            
            if score < 75:
                if self.args.log_nc:
                    with open(self.args.log_nc, "a") as log_nc:
                        log_nc.write("{}\n".format(domain))
                self.domain_queue.task_done()
                continue

            if score >= 120:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, "red", attrs=["underline", "bold"]), score))
            elif score >= 90:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, "yellow", attrs=["underline"]), score))
            elif score >= 75:
                tqdm.tqdm.write("[!] Likely    : {} (score={})".format(colored(domain, "cyan", attrs=["underline"]), score))

            url = "http://{}".format(domain)

            if not url in list(self.url_queue.queue):
                self.url_queue.put(url)

                with open("queue_file.txt", "a") as qfile:
                    qfile.write("{}\n".format(url))
            self.domain_queue.task_done()
        return

# hxxp://sebastiandahlgren[.]se/2014/06/27/running-a-method-as-a-background-thread-in-python/
class UrlQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, url_queue, proxies, uagent, suspicious, day, torsocks):
        """ """
        self.args       = args
        self.url_queue  = url_queue
        self.proxies    = proxies
        self.uagent     = uagent
        self.suspicious = suspicious
        self.day        = day
        self.torsocks   = torsocks

        for thread in range(self.args.threads):
            worker = threading.Thread(target=self.check_site)
            worker.daemon = True
            worker.start()

    def check_site(self):
        """ """
        while True:
            url = self.url_queue.get()

            with open("queue_file.txt", "w") as qfile:
                for q in list(self.url_queue.queue):
                    qfile.write("{}\n".format(q))

            tqdm.tqdm.write("[*] Session   : {}".format(colored(url, "blue")))
            try:
                resp = requests.get(url,
                                    proxies=self.proxies,
                                    headers={"User-Agent": self.uagent},
                                    timeout=self.args.timeout,
                                    allow_redirects=True,
                                    verify=False)
            except Exception as err:
                failed_message(self.args, err, url)
                self.url_queue.task_done()
                continue

            if not (resp.status_code == 200 and "Index of " in resp.content):
                self.url_queue.task_done()
                continue

            if resp.status_code == 200 and "wordpress/<" in resp.content:
                self.url_queue.task_done()
                continue

            extensions = self.suspicious["archives"].keys() + self.suspicious["files"].keys()

            for ext in extensions:
                if "{}<".format(ext) in resp.content.lower() and ext in self.suspicious["archives"]:
                    directory = "{}{}/".format(self.args.kit_dir, self.day)
                elif "{}<".format(ext) in resp.content.lower() and ext in self.suspicious["files"]:
                    directory = "{}{}/".format(self.args.file_dir, self.day)
                else:
                    continue

                tqdm.tqdm.write("[*] Download  : {} ('Index of ' found)".format(
                        colored(url, "green", attrs=["bold"])))

                try:
                    if not os.path.exists(directory):
                        os.makedirs(directory)

                    if not os.path.exists(directory):
                        tqdm.tqdm.write(colored("[!] Directory: {} is temporarily unavailable.".format(directory), "red", attrs=["underline"]))
                        tqdm.tqdm.write(colored("[!] Directory: Waiting 60s for {} to become available...".format(directory), "red", attrs=["underline"]))
                        time.sleep(60)

                    wget_command = format_wget(self.args,
                                               directory,
                                               self.uagent,
                                               self.torsocks,
                                               url)

                    subprocess.call(wget_command)

                    tqdm.tqdm.write("[*] Complete  : {}".format(
                            colored(url, "green", attrs=["bold", "underline"])))
                    break
                except Exception as err:
                    failed_message(self.args, err, url)
                    continue

            self.url_queue.task_done()
        return

def external_error(key, filename):
    """ """
    print(colored(
        "No {} found in {}.yaml ({}:).".format(key, filename, key),
        "red",
        attrs=["bold"]
    ))
    exit()
    
def failed_message(args, err, message):
    """ """
    if args.verbose:
        tqdm.tqdm.write("[!] Error    : {}".format(
            colored(err, "red", attrs=["bold", "underline"])
        ))

    if message == None:
        message = "Use --verbose to capture the error message."

    tqdm.tqdm.write("[!] Failed    : {}".format(
        colored(message, "red", attrs=["underline"])
    ))
    return

def fix_directory(args):
    """ """
    if not args.kit_dir.endswith("/"):
        args.kit_dir = "{}/".format(args.kit_dir)

    if not args.file_dir.endswith("/"):
        args.file_dir = "{}/".format(args.file_dir)
    return args

def format_wget(args, directory, uagent, torsocks, url):
    """Return the wget command needed to download files."""

    wget_command = [
        "wget",
        "--execute=robots=off",
        "--tries=2",
        "--no-clobber",
        "--timeout={}".format(args.timeout),
        "--waitretry=0",
        "--directory-prefix={}".format(directory),
        "--header='User-Agent: {}'".format(uagent),
        "--content-disposition",
        "--no-check-certificate",
        "--recursive",
        "--level={}".format(args.level),
        "--no-parent"
    ]

    if torsocks is not None:
        wget_command.insert(0, torsocks)

    if args.quiet:
        wget_command.append("--quiet")

    wget_command.append(url)
    return wget_command

def read_externals():
    """ """
    with open("external.yaml", "r") as f:
        external = yaml.safe_load(f)
            
    with open("suspicious.yaml", "r") as f:
        suspicious = yaml.safe_load(f)

    for key in suspicious.keys():
        if suspicious[key] is None:
            external_error(key, "suspicious")
            exit()

    if external["override_suspicious.yaml"] is True:
        suspicious = external

        for key in external.keys():
            if external[key] is None:
                external_error(key, "external")
                exit()
        return suspicious

    for key in external.keys():
        if (key == "keywords" or key == "tlds") and external[key] is not None:
            suspicious[key].update(external[key])
        elif external[key] is not None:
            suspicious[key] = external[key]
    return suspicious

def recompile_exclusions(regex_exclusions):
    """ """
    exclusions = []

    for exclusion in regex_exclusions:
        exclusions.append(re.compile(exclusion, re.IGNORECASE))
    return exclusions

def score_domain(suspicious, domain, args):
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
        failed_message(args, err, domain)
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

def show_network(args, uagent):
    """Select network to use, get IP address, and print message"""
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
        failed_message(args, err, None)
        exit()

    print(colored("Getting IP Address...", "yellow", attrs=["bold"]))

    if args.tor:
        obfuscated_ip = ".".join(["XXX.XXX.XXX", requested_ip.split(".")[:-1][0]])
        print(colored("{} IP: {}\n".format(ip_type, obfuscated_ip), "yellow", attrs=["bold"]))
    else:
        print(colored("{} IP: {}\n".format(ip_type, requested_ip), "yellow", attrs=["bold"]))
    return proxies, torsocks

def show_summary(args):
    """Print summary of arguments selected"""

    print("Summary:")
    if "query_type" in args and args.query_type:
        print("    query_type     : {}".format(args.query_type.lower()))
    if "delta" in args and args.delta:
        print("    delta          : {}".format(args.delta))
    if "exclude" in args and args.exclude:
        print("    exclusions     : {}".format(args.exclude.split(",")))
    print("    file_dir       : {}".format(args.file_dir))
    if "file_extension" in args and args.file_extension:
        print("    file_extension : {}".format(args.file_extension.lower()))
    print("    kit_dir        : {}".format(args.kit_dir))
    if "log_nc" in args and args.log_nc:
        print("    log_file       : {}".format(args.log_nc))
    print("    quiet          : {}".format(args.quiet))
    print("    timeout        : {}".format(args.timeout))
    print("    threads        : {}".format(args.threads))
    print("    tor            : {}".format(args.tor))
    print("    verbose        : {}\n".format(args.verbose))
    return

def threat_master(threads, target, data):
    """ """
    for thread in range(threads):
        worker = threading.Thread(target=target, args=(data))
        worker.setDaemon(True)
        worker.start()
    return
