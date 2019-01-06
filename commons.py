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

import base64
from datetime import date
from datetime import datetime
from datetime import timedelta
import glob
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
import entropy
from Levenshtein import distance
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import subprocess
from termcolor import colored, cprint
from tld import get_tld
import tqdm
import yaml

from confusables import unconfuse


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

        for thread in range(self.args.threads):
            worker = threading.Thread(target=self.return_suspicious)
            worker.daemon = True
            worker.start()

    def return_suspicious(self):
        """ """
        while True:
            domain = self.domain_queue.get()
            score  = score_domain(suspicious, domain.lower(), self.args)

            match_found = False
            for exclusion in exclusions:
                if exclusion.match(domain):
                    match_found = True
                    break
            
            if match_found:
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

class RecursiveQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, recursion_queue, uagent, extensions):
        """ """
        self.args             = args
        self.recursion_queue  = recursion_queue
        self.uagent           = uagent
        self.extensions       = extensions
        self.day              = date.today()

        print(colored("Creating {} threads...\n".format(self.args.threads), "yellow", attrs=["bold"]))

        for thread in range(self.args.threads):
            worker = threading.Thread(target=self.check_site)
            worker.daemon = True
            worker.start()

    def check_site(self):
        """ """
        while True:
            url = self.recursion_queue.get()

            # Check if the current URL has already been redirected to
            if "redirect" in vars() and redirect == url:
                del redirect
                continue

            # Split URL into parts
            split_url = url.split("/")
            protocol  = split_url[0]
            domain    = split_url[2].split(":")[0]

            match_found = False
            for exclusion in exclusions:
                if exclusion.match(domain):
                    match_found = True
                    break
            
            if match_found:
                tqdm.tqdm.write("[*] Excluded : {}".format(colored(url, "red")))
                self.recursion_queue.task_done()
                continue

            tqdm.tqdm.write("[*] Original : {}".format(colored(url, "cyan")))
            url = "//".join([protocol, domain])

            # Build list of URL resources
            resources = split_url[3:]
            resources = ['/{}'.format(x) for x in resources]
            resources.insert(0, "")

            for resource in resources:
                # Combine current URL and resource
                url = "{}{}".format(url, resource)

                # Send first request to the URL
                tqdm.tqdm.write("[*] Session  : {}".format(colored(url, "blue")))

                try:
                    resp = requests.get(url,
                                        proxies=proxies,
                                        headers={"User-Agent": self.uagent},
                                        timeout=self.args.timeout,
                                        allow_redirects=True)
                except Exception as err:
                    failed_message(self.args, err, url)
                    continue

                if resp.status_code != 200 or "wordpress/<" in resp.content:
                    continue

                if glob.glob("./*/{}/{}".format(self.day, domain)):
                    tqdm.tqdm.write("[-] Skipping : {} (Directory '{}' already exists)".format(
                        colored(url, "red"),
                        domain
                    ))
                    break

                # An open directory is found
                if "Index of " in resp.content:
                    for extension in self.extensions.keys():
                        if ".{}<".format(extension) in resp.content.lower() and extension in suspicious["archives"]:
                            directory = "{}{}/".format(self.args.kit_dir, self.day)
                        elif ".{}<".format(self.args.ext) in resp.content.lower() and extension in suspicious["files"]:
                            directory = "{}{}/".format(self.args.file_dir, self.day)
                        else:
                            continue

                        download_message("('Index of ' found)", url)

                        action = download_site(directory, domain, self.args, self.uagent, url)
                        if action == "break":
                            break
                        elif action == "continue":
                            continue

                # A URL is found ending in the specified extension but the server responded with no Content-Type
                if "Content-Type" not in resp.headers.keys():
                    directory = "{}{}/".format(self.args.file_dir, self.day)

                    if url.endswith('.{}'.format(self.args.ext)):
                        if resp.url != url:
                            redirect = redirect_message(resp)
                        else:
                            download_message("(Responded with no Content-Type)", url)

                        action = download_site(directory, domain, self.args, self.uagent, url)
                        if action == "break":
                            break
                        elif action == "continue":
                            continue

                # A file is found with the Mime-Type of the specified extension
                if resp.headers["Content-Type"].startswith(self.extensions[self.args.ext]) or url.endswith(".{}".format(self.args.ext)):
                    directory = "{}{}/".format(self.args.file_dir, self.day)

                    if resp.url != url:
                        redirect = redirect_message(resp)
                    else:
                        download_message("({} found)".format(self.args.ext), url)
                    
                    action = download_site(directory, domain, self.args, self.uagent, url)
                    if action == "break":
                        break
                    elif action == "continue":
                        continue
            self.recursion_queue.task_done()
        return

class UrlQueueManager():
    """
    The run() method will be started and it will run in the background
    until the application exits.
    """

    def __init__(self, args, url_queue, uagent):
        """ """
        self.args       = args
        self.url_queue  = url_queue
        self.uagent     = uagent
        self.day        = date.today()

        print(colored("Creating {} threads...\n".format(self.args.threads), "yellow", attrs=["bold"]))

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
                                    proxies=proxies,
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

            extensions = suspicious["archives"].keys() + suspicious["files"].keys()

            for ext in extensions:
                if "{}<".format(ext) in resp.content.lower() and ext in suspicious["archives"]:
                    directory = "{}{}/".format(self.args.kit_dir, self.day)
                elif "{}<".format(ext) in resp.content.lower() and ext in suspicious["files"]:
                    directory = "{}{}/".format(self.args.file_dir, self.day)
                else:
                    continue

                download_message("('Index of ' found)", url)

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
                                               url)

                    subprocess.call(wget_command)

                    complete_message(url)
                    break
                except Exception as err:
                    failed_message(self.args, err, url)
                    continue

            self.url_queue.task_done()
        return

def check_path(args):
    """ """
    if not (os.path.exists(args.kit_dir) or os.path.exists(args.file_dir)):
        print(colored("Either the file or kit directory is temporarily unavailable. Exiting!", "red", attrs=["underline"]))
        exit()
    return

def create_queue(queue_name):
    """ """
    print(colored("Starting the {}...\n".format(queue_name), "yellow", attrs=["bold"]))
    return Queue.Queue()

def complete_message(url):
    """ """
    tqdm.tqdm.write("[*] Complete : {}".format(
        colored(url, "green", attrs=["bold", "underline"])
    ))
    return

def download_message(comment, url):
    """ """
    tqdm.tqdm.write("[*] Download  : {} {}".format(
        colored(url, "green", attrs=["bold"]), comment))
    return

def download_site(directory, domain, args, uagent, url):
    """ """
    try:
        if not os.path.exists(directory):
            os.makedirs("{}{}".format(directory, domain))

        wget_command = format_wget(args,
                                   directory,
                                   uagent,
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
    if args.verbose:
        tqdm.tqdm.write("[!] Error     : {}".format(
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

def format_wget(args, directory, uagent, url):
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
        resp = requests.get(whoisds.format(encoded_filename))
    except Exception as err:
        failed_message(args, err, None)

        try:
            print(colored("Attempting to get domain list using plain-text filename...", "yellow", attrs=["bold"]))
            resp = requests.get(whoisds.format(filename))
        except Exception as err:
            failed_message(args, err, None)
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
        failed_message(args, err, None)
        exit()

    with open(new_name, "r") as open_df:
        domains = open_df.read().splitlines()

    os.remove(old_name)
    os.remove(new_name)
    return domains

def query_urlscan(args, queries, uagent, extensions):
    """Request URLs from urlscan.io"""
    try:
        print(colored("Querying urlscan.io for URLs based on provided parameters...\n", "yellow", attrs=["bold"]))
        api  = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename%3A.{}&size=10000"
        resp = requests.get(api.format(queries[args.query_type], args.ext),
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
                if filename["mimeType"].startswith(extensions[args.ext]):
                    urls.append(url)
                    break
    return urls

def read_externals():
    """ """
    global suspicious

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

    if "exclusions" in suspicious.keys():
        for exclusion in suspicious["exclusions"]:
            exclusions.append(re.compile(exclusion, re.IGNORECASE))
    return exclusions

def redirect_message(resp):
    """ """
    redirect = resp.url
    tqdm.tqdm.write("[*] Redirect : {} (Responded with no Content-Type)".format(
        colored(redirect, "green")
    ))
    return redirect

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

def show_networking(args, uagent):
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
