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
        self.extensions = config["extensions"]
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
            protocol  = split_url[0]
            domain    = split_url[2].split(":")[0]

            try:
                resp = send_request(url, proxies, uagent, self.args)
            except Exception as err:
                message_failed(self.args, err, url)
                self.url_queue.task_done()
                continue

            if resp.status_code != 200:
                self.url_queue.task_done()
                continue

            # Open Directory
            if "index of /" in resp.content.lower():
                message_download("('Index of /' found)", url)
                download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
            # Banking phish
            elif ">interac e-transfer<" in resp.content.lower() and ">select your financial institution<" in resp.content.lower():
                message_download("(Banking phish found)", url)
                self.ext_csv = self.ext_csv + "html,php"
                download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
                self.ext_csv = self.ext_csv[-8]
            # Deliberate obfuscation - suspicious
            elif "<script>document.write(unescape('" in resp.content.lower():
                message_download("(Obfuscated Javascript found)", url)
                self.ext_csv = self.ext_csv + "html,php"
                download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
                self.ext_csv = self.ext_csv[-8]
            # Hosted file
            elif "Content-Disposition" in resp.headers and not resp.headers["Content-Type"].startswith("text"):
                message_download("(Attachment found)", url)
                download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
            # String seen in downloaded file during urlscan.io scan
            elif "query_string" in self.args and self.args.query_string in url:
                message_download("(Query String found)", url)
                download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
            # Catch-all - search for extensions in URL
            else:
                for ext in self.extensions:
                    if not (url.endswith(".{}".format(ext)) or ".{}/".format(ext) in url or ".{}?".format(ext) in url):
                        continue

                    message_download("(Extension found)", url)

                    action = download_site(self.args, day, protocol, domain, self.ext_csv, url, resp)
                    if action == "break":
                        break
                    elif action == "continue":
                        continue
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

def download_site(args, day, protocol, domain, ext_csv, url, resp):
    """ """
    directory  = "{}{}".format(args.cap_dir, day)
    domain_dir = "{}/{}".format(directory, domain)
    root_url   = "{}//{}/".format(protocol, domain)

    try:
        if not os.path.exists(domain_dir):
            os.makedirs(domain_dir)

        if not os.path.exists(domain_dir):
            tqdm.tqdm.write(colored("{}: {} is temporarily unavailable.".format(
                message_header("directory"), 
                domain_dir
            ), "red", attrs=["underline"]))
            tqdm.tqdm.write(colored("{}: Waiting 15s for {} to become available...".format(
                message_header("directory"), 
                domain_dir), "red", attrs=["underline"]
            ))
            time.sleep(15)
        
        if not os.path.exists(domain_dir):
            return "continue"

        wget_command = format_wget(args, directory, uagent, ext_csv, root_url)
        proc     = subprocess.Popen(wget_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        _, err = proc.communicate()

        if "301 Moved Permanently" in err or "302 Found" in err or "307 Temporary Redirect" in err:
            message_failed(args, "Redirects exceeded", root_url)
            os.rmdir(domain_dir)
            return "continue"

        message_complete(url)
        remove_empty(domain_dir, args)
        return "break"
    except Exception as err:
        message_failed(args, err, url)
        remove_empty(domain_dir, args)
        return "continue"

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
        "--server-response",
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

    if "max_redirect" in args:
        wget_command.append("--max-redirect={}".format(args.max_redirect))

    if args.quiet:
        wget_command.append("--quiet")

    if torsocks is not None:
        wget_command.insert(0, torsocks)

    wget_command.append(url)
    return wget_command

def get_domains(args):
    """ """
    # Get the date to determine which file to download
    now = datetime.now()
    day = datetime.strftime(now - timedelta(args.delta), "%Y-%m-%d")

    filename = "{}.zip".format(day)
    encoded_filename = base64.b64encode(filename)
    whoisds = "https://whoisds.com//whois-database/newly-registered-domains/{}/nrd"

    try:
        print(colored("Attempting to get domain list using encoded filename...", "yellow", attrs=["bold"]))
        resp = send_request(whoisds.format(encoded_filename), proxies, uagent, args)
    except Exception as err:
        message_failed(args, err, None)

        try:
            print(colored("Attempting to get domain list using plain-text filename...", "yellow", attrs=["bold"]))
            resp = send_request(whoisds.format(filename), proxies, uagent, args)
        except Exception as err:
            message_failed(args, err, None)
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
        message_failed(args, err, None)
        exit()

    with open(txt_name, "r") as open_df:
        domains = open_df.read().splitlines()

    os.remove(zip_name)
    os.remove(txt_name)
    return domains

def message_complete(url):
    """ """
    tqdm.tqdm.write("{}: {}".format(
        message_header("complete"), 
        colored(url, "green", attrs=["bold", "underline"])
    ))
    return

def message_download(comment, url):
    """ """
    tqdm.tqdm.write("{}: {} {}".format(
        message_header("download"), 
        colored(url, "green", attrs=["bold"]),
        comment
    ))
    return

def message_external(key, filename):
    """ """
    tqdm.tqdm.write(colored(
        "No {} found in {}.yaml ({}:).".format(key, filename, key), "red", attrs=["bold"]
    ))
    exit()
    
def message_failed(args, err, message):
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

def message_header(message_type):
    """ """
    headers = {
        "complete"  : "[+] Complete  ",
        "critical"  : "[!] Critical  ",
        "crtsh"     : "[^] Crt.sh    ",
        "directory" : "[/] Directory ",
        "download"  : "[~] Download  ",
        "empty"     : "[X] Empty     ",
        "error"     : "[!] Error     ",
        "failed"    : "[!] Failed    ",
        "session"   : "[?] Session   ",
        "suspicious": "[!] Suspicious",
        "triggered" : "[!] Triggered "
    }
    return headers[message_type]

def query_urlscan(args):
    """Request URLs from urlscan.io"""
    # Get stopping point
    now      = datetime.now()
    timespan = datetime.strftime(now - timedelta(args.delta), "%a, %d %b %Y 05:00:00")
    timespan = datetime.strptime(timespan, "%a, %d %b %Y %H:%M:%S")

    try:
        print(colored("Querying urlscan.io for URLs...\n", "yellow", attrs=["bold"]))
        urlscan  = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename%3A{}&size=10000"
        endpoint = urlscan.format(config["queries"][args.query_type], args.query_string)
        resp     = send_request(endpoint, proxies, uagent, args)
    except Exception as err:
        message_failed(args, err, None)
        exit()

    try:
        if not (resp.status_code == 200 and "results" in resp.json().keys()):
            raise Exception
    except Exception as err:
        message_failed(args, err, None)
        exit()

    results = resp.json()["results"]
    urls    = []

    for result in results:
        analysis_time = datetime.strptime(result["task"]["time"], "%Y-%m-%dT%H:%M:%S.%fZ")

        # Break at delta specified
        if analysis_time < timespan:
            break

        urls.append(result["page"]["url"])
    return urls

def read_config(args):
    """ """
    global config
            
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    for key in config.keys():
        if key == "exclusions" and config[key] is None:
            message_external(key, "config")
            exit()

    if "dns_twist" in args and args.dns_twist:
        with open("dns_twisted.yaml", "r") as f:
            dns_twisted = yaml.safe_load(f)

        config["keywords"].update(dns_twisted["keywords"])
    return config

def read_file(input_file):
    """ """
    print(colored("Reading file containing URLs...\n", "yellow", attrs=["bold"]))
    
    with open(input_file, "r") as open_file:
        contents = open_file.read().splitlines()
    return contents

def recompile_exclusions():
    """ """
    global exclusions

    exclusions = []

    if "exclusions" in config.keys():
        for exclusion in config["exclusions"]:
            exclusions.append(re.compile(exclusion, re.IGNORECASE))
    return exclusions

def remove_empty(domain_dir, args):
    """Remove empty files and directories"""
    try:
        rm_files = ["find", domain_dir, "-empty", "-type", "f", "-delete"]
        subprocess.call(rm_files)

        chk_dirs = ["find", domain_dir, "-empty", "-type", "d"]
        chkdirs  = subprocess.Popen(chk_dirs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)        
        out, _   = chkdirs.communicate()

        if out == '':
            return False

        empty_dirs = filter(None, out.split("\n"))

        for empty_dir in empty_dirs:
            tqdm.tqdm.write("{}: {} (Removing)".format(
                message_header("empty"),
                colored(empty_dir, "red", attrs=["underline"])
            ))

        rm_dirs = ["find", domain_dir, "-empty", "-type", "d", "-delete"]
        subprocess.call(rm_dirs)
        return True
    except Exception as err:
        message_failed(args, err, domain_dir)
        return False

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
        message_failed(args, err, domain)
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

    ip_type  = "Original"
    proxies  = {}
    torsocks = None

    if args.tor:
        ip_type  = "Tor"
        proxies  = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
        torsocks = "torsocks"

    print(colored("\nGetting IP Address...", "yellow", attrs=["bold"]))
    try:
        endpoint = "https://api.ipify.org"
        resp     = send_request(endpoint, proxies, uagent, args)
        ip_addr  = resp.content
    except Exception as err:
        message_failed(args, err, None)
        exit()

    if args.tor:
        ip_addr = ".".join(["XXX.XXX.XXX", ip_addr.split(".")[:-1][0]])

    print(colored("{} IP: {}\n".format(ip_type, ip_addr), "yellow", attrs=["bold"]))
    return

def send_request(endpoint, proxies, uagent, args):
    """ """
    return requests.get(endpoint,
                        proxies=proxies,
                        headers={"User-Agent": uagent},
                        timeout=args.timeout,
                        allow_redirects=False,
                        verify=False)

def show_summary(args):
    """Print summary of arguments selected"""

    print("Summary:")
    if "ctl_server" in args:
        print("    ctl_server     : {}".format(args.ctl_server))
    if "delta" in args:
        print("    delta          : {}".format(args.delta))
    print("    directory      : {}".format(args.cap_dir))
    if "dns_twist" in args:
        print("    dns_twist      : {}".format(args.dns_twist))
    if "exclude" in args:
        print("    exclusions     : {}".format(args.exclude.split(",")))
    print("    level          : {}".format(args.level))
    if "log_nc" in args:
        print("    log_file       : {}".format(args.log_nc))
    if "max_redirect" in args:
        print("    max_redirect   : {}".format(args.max_redirect))
    if "score" in args:
        print("    minimum_score  : {}".format(args.score))
    if "query_string" in args:
        print("    query_string   : {}".format(args.query_string))
    if "query_type" in args:
        print("    query_type     : {}".format(args.query_type.lower()))
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
