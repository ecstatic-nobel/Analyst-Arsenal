#!/usr/bin/python
"""
Credit:
    https://github.com/ninoseki/miteru
    https://github.com/x0rz/phishing_catcher

Resources:
    http://docs.python-requests.org/en/master/user/advanced/#proxies
    http://sebastiandahlgren[.]se/2014/06/27/running-a-method-as-a-background-thread-in-python/
    https://ec.haxx.se/libcurl-proxies.html
    https://gist.github.com/jefftriplett/9748036
    https://trac.torproject.org/projects/tor/wiki/doc/torsocks
    https://urlscan.io/search/#*
    https://whoisds.com/newly-registered-domains
"""

from datetime import date
from datetime import datetime
from datetime import timedelta
import base64
import glob
import json
import os
import Queue
import re
import subprocess
import sys
import threading
import time
import zipfile

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
from Levenshtein import distance
import entropy
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from termcolor import colored, cprint
from tld import get_tld
import subprocess
import tqdm
import yaml

from confusables import unconfuse


tqdm.tqdm.monitor_interval = 0
uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

class DomainQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, domain_queue, url_queue):
        """ """
        self.args         = args
        self.domain_queue = domain_queue
        self.url_queue    = url_queue

        thread_master(self.args.threads, self.return_suspicious)

    def return_suspicious(self):
        """ """
        while True:
            domain = self.domain_queue.get()

            if domain.startswith("*."):
                domain = domain[2:]

            match_found = False
            for exclusion in exclusions:
                if exclusion.search(domain):
                    match_found = True
                    break
            
            if match_found:
                self.domain_queue.task_done()
                continue

            score = score_domain(config, domain.lower(), self.args)
            
            if score < self.args.score:
                if self.args.log_nc:
                    with open(self.args.log_nc, "a") as log_nc:
                        log_nc.write("{}\n".format(domain))
                self.domain_queue.task_done()
                continue

            if self.args.verbose:
                if score >= 120:
                    tqdm.tqdm.write("{}: {} (score={})".format(
                        message_header("critical"), 
                        colored(domain, "red", attrs=["underline", "bold"]), 
                        score)
                    )
                elif score >= 90:
                    tqdm.tqdm.write("{}: {} (score={})".format(
                        message_header("suspicious"), 
                        colored(domain, "yellow", attrs=["underline"]), 
                        score)
                    )
                elif score >= self.args.score:
                    tqdm.tqdm.write("{}: {} (score={})".format(
                        message_header("triggered"), 
                        colored(domain, "cyan", attrs=["underline"]), 
                        score)
                    )

            url = "http://{}".format(domain)

            if not url in list(self.url_queue.queue):
                self.url_queue.put(url)

                with open("queue_file.txt", "a") as qfile:
                    qfile.write("{}\n".format(url))
            self.domain_queue.task_done()
        return

class UrlQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, url_queue):
        """ """
        # globals config
        # globals exclusions
        # globals proxies
        # globals torsocks
        self.args       = args
        self.url_queue  = url_queue
        self.extensions = config["extensions"].keys()
        self.ext_csv    = ",".join(self.extensions)

        print(colored("Creating {} threads...\n".format(self.args.threads), "yellow", attrs=["bold"]))

        thread_master(self.args.threads, self.check_site)

    def check_site(self):
        """ """
        while True:
            url = self.url_queue.get()
            day = date.today()

            if "delta" in self.args:
                day = datetime.strftime(day - timedelta(self.args.delta), "%Y-%m-%d")

            with open("queue_file.txt", "w") as qfile:
                for q in list(self.url_queue.queue):
                    qfile.write("{}\n".format(q))

            tqdm.tqdm.write("{}: {}".format(
                message_header("session"),
                colored(url, "blue")
            ))
            
            # Split URL into parts
            split_url = url.split("/")
            domain    = split_url[2].split(":")[0]

            try:
                resp = requests.get(url,
                                    proxies=proxies,
                                    headers={"User-Agent": uagent},
                                    timeout=self.args.timeout,
                                    allow_redirects=False,
                                    verify=False)
            except Exception as err:
                failed_message(self.args, err, url)
                self.url_queue.task_done()
                continue

            if "wordpress/<" in resp.content or resp.status_code != 200:
                self.url_queue.task_done()
                continue

            if "Index of /" in resp.content:
                for ext in self.extensions:
                    if ".{}<".format(ext) not in resp.content.lower():
                        continue

                    download_message("('Index of /' found)", url)

                    action = download_site(self.args, day, domain, self.ext_csv, url)
                    if action == "break":
                        break
                    elif action == "continue":
                        continue
            elif "Content-Disposition" in resp.headers:
                attachment = resp.headers["Content-Disposition"].split("=")[1].replace('"', '')

                if "ext" in self.args and attachment.endswith(".{}".format(self.args.ext)):
                    download_message("(Attachment found)", url)
                    download_site(self.args, day, domain, self.ext_csv, url)
            self.url_queue.task_done()
        return

def check_path(args):
    """ """
    if not (os.path.exists(args.cap_dir)):
        print(colored("The output directory is temporarily unavailable. Exiting!", "red", attrs=["underline"]))
        exit()
    return

def create_queue(queue_name):
    """ """
    print(colored("Starting the {}...\n".format(queue_name), "yellow", attrs=["bold"]))
    return Queue.Queue()

def complete_message(url):
    """ """
    tqdm.tqdm.write("{}: {}".format(
        message_header("complete"), 
        colored(url, "green", attrs=["bold", "underline"])
    ))
    return

def download_message(comment, url):
    """ """
    tqdm.tqdm.write("{}: {} {}".format(
        message_header("download"), 
        colored(url, "green", attrs=["bold"]), comment))
    return

def download_site(args, day, domain, ext_csv, url):
    """ """
    directory = "{}{}".format(args.cap_dir, day)

    try:
        if not os.path.exists("{}/{}".format(directory, domain)):
            os.makedirs("{}/{}".format(directory, domain))

        if not os.path.exists("{}/{}".format(directory, domain)):
            tqdm.tqdm.write(colored("{}: {} is temporarily unavailable.".format(
                message_header("directory"), 
                "{}/{}".format(directory, domain)
            ), "red", attrs=["underline"]))
            tqdm.tqdm.write(colored("{}: Waiting 60s for {} to become available...".format(
                message_header("directory"), 
                "{}/{}".format(directory, domain)), "red", attrs=["underline"]
            ))
            time.sleep(60)

        wget_command = format_wget(args,
                                   directory,
                                   uagent,
                                   ext_csv,
                                   url)

        subprocess.call(wget_command)

        complete_message(url)
        return "break"
    except Exception as err:
        failed_message(args, err, url)
        return "continue"

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
    if args.very_verbose:
        tqdm.tqdm.write("{}: {}".format(
            message_header("error"), 
            colored(err, "red", attrs=["bold", "underline"])
        ))

    if message == None:
        message = "Use --very-verbose to capture the error message."

    tqdm.tqdm.write("{}: {}".format(
        message_header("failed"), 
        colored(message, "red", attrs=["underline"])
    ))
    return

def fix_directory(args):
    """ """
    if not args.cap_dir.endswith("/"):
        args.cap_dir = "{}/".format(args.cap_dir)
    return args

def format_wget(args, directory, uagent, ext_csv, url):
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
        "--accept={}".format(ext_csv),
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

def get_domains(args):
    """ """
    # Get dates
    now = datetime.now()
    day = datetime.strftime(now - timedelta(args.delta), "%Y-%m-%d")

    filename = "{}.zip".format(day)
    encoded_filename = base64.b64encode(filename)
    whoisds = "https://whoisds.com//whois-database/newly-registered-domains/{}/nrd"

    try:
        print(colored("Attempting to get domain list using encoded filename...", "yellow", attrs=["bold"]))
        resp = requests.get(whoisds.format(encoded_filename),
                            proxies=proxies,
                            headers={"User-Agent": uagent},
                            timeout=args.timeout,
                            allow_redirects=True)
    except Exception as err:
        failed_message(args, err, None)

        try:
            print(colored("Attempting to get domain list using plain-text filename...", "yellow", attrs=["bold"]))
            resp = requests.get(whoisds.format(filename),
                                proxies=proxies,
                                headers={"User-Agent": uagent},
                                timeout=args.timeout,
                                allow_redirects=True)
        except Exception as err:
            failed_message(args, err, None)
            exit()

    try:
        if resp.status_code == 200 and filename in resp.headers["Content-Disposition"]:
            print(colored("Download successful...\n", "yellow", attrs=["bold"]))

            content_disposition = resp.headers["Content-Disposition"].replace("attachment; filename=", "")
            content_disposition = content_disposition.replace('"', "")
            zip_name = "{}{}".format(args.cap_dir, content_disposition)
            txt_name = zip_name.replace(".zip", ".txt")

            with open(zip_name, "wb") as cd:
                cd.write(resp.content)

            compressed_file = zipfile.ZipFile(zip_name).namelist()[0]
            zipfile.ZipFile(zip_name).extractall(args.cap_dir)
            os.rename("{}{}".format(args.cap_dir, compressed_file), txt_name)
        else:
            raise ValueError("Newly registered domains file was not downloaded successfully.")
    except Exception as err:
        failed_message(args, err, None)
        exit()

    with open(txt_name, "r") as open_df:
        domains = open_df.read().splitlines()

    os.remove(zip_name)
    os.remove(txt_name)
    return domains

def message_header(message_type):
    """ """
    headers = {
        "complete"  : "[+] Complete  ",
        "critical"  : "[!] Critical  ",
        "directory" : "[/] Directory ",
        "download"  : "[~] Download  ",
        "error"     : "[!] Error     ",
        "excluded"  : "[*] Excluded  ",
        "failed"    : "[!] Failed    ",
        "likely"    : "[!] Likely    ",
        "original"  : "[*] Original  ",
        "redirect"  : "[>] Redirect  ",
        "session"   : "[?] Session   ",
        "skipping"  : "[-] Skipping  ",
        "triggered" : "[!] Triggered ",
        "suspicious": "[!] Suspicious"
    }
    return headers[message_type]

def query_urlscan(args):
    """Request URLs from urlscan.io"""
    try:
        print(colored("Querying urlscan.io for URLs...\n", "yellow", attrs=["bold"]))
        api  = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename%3A.{}&size=10000"
        resp = requests.get(api.format(config["queries"][args.query_type], args.ext),
                            proxies=proxies,
                            headers={"User-Agent": uagent},
                            timeout=args.timeout,
                            allow_redirects=True)
    except Exception as err:
        failed_message(args, err, None)
        exit()

    try:
        if not (resp.status_code == 200 and "results" in resp.json().keys()):
            raise Exception
    except Exception as err:
        failed_message(args, err, None)
        exit()

    results  = resp.json()["results"]
    # Get stopping point
    now      = datetime.now()
    timespan = datetime.strftime(now - timedelta(args.delta), "%a, %d %b %Y 05:00:00")
    timespan = datetime.strptime(timespan, "%a, %d %b %Y %H:%M:%S")
    urls     = []

    for result in results:
        # Break at delta specified
        analysis_time = datetime.strptime(result["task"]["time"], "%Y-%m-%dT%H:%M:%S.%fZ")

        if analysis_time < timespan:
            break

        url = result["page"]["url"]

        # Build list of URLs ending with specified extension or Mime-Type
        if url.endswith('.{}'.format(args.ext)):
            urls.append(url)
            continue
    
        if "files" in result.keys():
            for filename in result["files"]:
                if filename["mimeType"].startswith(config["extensions"][args.ext]):
                    urls.append(url)
                    break
    return urls

def read_config(args):
    """ """
    global config
            
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    for key in config.keys():
        if key != "extensions" and config[key] is None:
            external_error(key, "config")
            exit()

    if "dns_twist" in args:
        with open("dns_twisted.yaml", "r") as f:
            dns_twisted = yaml.safe_load(f)

        config["keywords"].update(dns_twisted["keywords"])
    return config

def read_file(input_file):
    """ """
    print(colored("Reading file containing URLs...\n", "yellow", attrs=["bold"]))
    
    open_file = open(input_file, "r")
    contents  = open_file.read().splitlines()
    open_file.close()

    return contents

def recompile_exclusions():
    """ """
    global exclusions
    exclusions = []

    if "exclusions" in config.keys():
        for exclusion in config["exclusions"]:
            exclusions.append(re.compile(exclusion, re.IGNORECASE))
    return exclusions

def redirect_message(resp):
    """ """
    redirect = resp.url
    tqdm.tqdm.write("{}: {} (Responded with no Content-Type)".format(
        message_header("redirect"), 
        colored(redirect, "green")
    ))
    return redirect

def score_domain(config, domain, args):
    """ """
    score = 0
    for t in config["tlds"]:
        if domain.endswith(t):
            score += 20

    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)

        if res is not None:
            domain = '.'.join([res.subdomain, res.domain])
    except Exception as err:
        failed_message(args, err, domain)
        pass

    score += int(round(entropy.shannon_entropy(domain)*50))

    domain          = unconfuse(domain)
    words_in_domain = re.split(r"\W+", domain)

    if words_in_domain[0] in ["com", "net", "org"]:
        score += 10

    for word in config["keywords"]:
        if word in domain:
            score += config["keywords"][word]

    for key in [k for (k,s) in config["keywords"].items() if s >= 70]:
        for word in [w for w in words_in_domain if w not in ["email", "mail", "cloud"]]:
            if distance(str(word), str(key)) == 1:
                score += 70

    if "xn--" not in domain and domain.count("-") >= 4:
        score += domain.count("-") * 3

    if domain.count(".") >= 3:
        score += domain.count(".") * 3

    return score

def show_networking(args):
    """Select network to use, get IP address, and print message"""
    global proxies
    global torsocks

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

    print(colored("\nGetting IP Address...", "yellow", attrs=["bold"]))

    if args.tor:
        obfuscated_ip = ".".join(["XXX.XXX.XXX", requested_ip.split(".")[:-1][0]])
        print(colored("{} IP: {}\n".format(ip_type, obfuscated_ip), "yellow", attrs=["bold"]))
    else:
        print(colored("{} IP: {}\n".format(ip_type, requested_ip), "yellow", attrs=["bold"]))
    return

def show_summary(args):
    """Print summary of arguments selected"""

    print("Summary:")
    if "query_type" in args:
        print("    query_type     : {}".format(args.query_type.lower()))
    if "delta" in args:
        print("    delta          : {}".format(args.delta))
    if "ext" in args:
        print("    extension      : {}".format(args.ext))
    print("    directory      : {}".format(args.cap_dir))
    if "dns_twist" in args:
        print("    dns_twist      : {}".format(args.dns_twist))
    if "exclude" in args:
        print("    exclusions     : {}".format(args.exclude.split(",")))
    print("    level          : {}".format(args.level))
    if "log_nc" in args:
        print("    log_file       : {}".format(args.log_nc))
    print("    quiet          : {}".format(args.quiet))
    if "score" in args:
        print("    minimum_score  : {}".format(args.score))
    print("    quiet          : {}".format(args.quiet))
    print("    threads        : {}".format(args.threads))
    print("    timeout        : {}".format(args.timeout))
    print("    tor            : {}".format(args.tor))
    if "verbose" in args:
        print("    verbose        : {}".format(args.verbose))
    if "very_verbose" in args:
        print("    verbose+       : {}".format(args.very_verbose))
    return

def thread_master(threads, target):
    """ """
    for thread in range(threads):
        worker = threading.Thread(target=target)
        worker.setDaemon(True)
        worker.start()
    return
