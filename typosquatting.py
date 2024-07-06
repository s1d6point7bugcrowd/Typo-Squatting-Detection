# Ensure all dependencies are installed
# Install required packages using the following command:
# pip install requests beautifulsoup4 scikit-learn python-whois dnspython ipwhois colorama

import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from urllib.parse import urlparse
import whois
import ssl
import socket
import dns.resolver
from ipwhois import IPWhois
from ipwhois.utils import get_countries
import urllib3
from colorama import init, Fore, Style
import argparse
import time

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to generate potential typos
def generate_typos(domain):
    typos = set()
    domain_name, extension = domain.rsplit('.', 1)
    # Swap adjacent characters
    for i in range(len(domain_name) - 1):
        swapped = list(domain_name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        typos.add(''.join(swapped) + '.' + extension)

    # Omission of a character
    for i in range(len(domain_name)):
        typos.add(domain_name[:i] + domain_name[i + 1:] + '.' + extension)

    # Repetition of a character
    for i in range(len(domain_name)):
        typos.add(domain_name[:i] + domain_name[i] + domain_name[i:] + '.' + extension)

    # Insertion of a character
    for i in range(len(domain_name) + 1):
        for char in 'abcdefghijklmnopqrstuvwxyz':
            typos.add(domain_name[:i] + char + domain_name[i:] + '.' + extension)

    # Substitution of a character
    for i in range(len(domain_name)):
        for char in 'abcdefghijklmnopqrstuvwxyz':
            typos.add(domain_name[:i] + char + domain_name[i + 1:] + '.' + extension)

    # Keyboard proximity errors
    keyboard_proximity = {
        'a': 'qwsz',
        'b': 'vghn',
        'c': 'xdfv',
        'd': 'erfcxs',
        'e': 'rdsw',
        'f': 'rtgvcd',
        'g': 'tyhbvf',
        'h': 'yujnbg',
        'i': 'uojk',
        'j': 'uikmnh',
        'k': 'iolmj',
        'l': 'opk',
        'm': 'njk',
        'n': 'bhjm',
        'o': 'pikl',
        'p': 'ol',
        'q': 'wa',
        'r': 'etdf',
        's': 'wedxz',
        't': 'rfgy',
        'u': 'yhji',
        'v': 'cfgb',
        'w': 'qase',
        'x': 'zsdc',
        'y': 'tghu',
        'z': 'asx'
    }

    for i in range(len(domain_name)):
        if domain_name[i] in keyboard_proximity:
            for char in keyboard_proximity[domain_name[i]]:
                typos.add(domain_name[:i] + char + domain_name[i + 1:] + '.' + extension)

    # Phonetic replacements
    phonetic_replacements = {
        'a': '4',
        'e': '3',
        'i': '1',
        'o': '0',
        's': '5',
        'g': '9'
    }

    for i in range(len(domain_name)):
        if domain_name[i] in phonetic_replacements:
            typos.add(domain_name[:i] + phonetic_replacements[domain_name[i]] + domain_name[i + 1:] + '.' + extension)

    # Common misspellings
    common_misspellings = {
        'example': ['exmaple', 'examle', 'exampel'],
        'google': ['gogle', 'gooogle', 'gogole', 'googl'],
        'facebook': ['facebok', 'faecbook', 'fcaebook'],
        'twitter': ['twiter', 'twittter', 'twtter'],
        'linkedin': ['linkdin', 'linkedn', 'linkeidn'],
        'github': ['githb', 'gihub', 'githu'],
        'microsoft': ['microsft', 'micorsoft', 'microosft'],
        'amazon': ['amzon', 'amaozn', 'amazn'],
        'instagram': ['instgram', 'intsagram', 'instagarm'],
        'netflix': ['netflx', 'netflxi', 'netlfix']
    }

    if domain_name in common_misspellings:
        for misspelling in common_misspellings[domain_name]:
            typos.add(misspelling + '.' + extension)

    # Homoglyphs
    homoglyphs = {
        'a': '@',
        'e': '3',
        'i': '1',
        'o': '0',
        'c': '(',
        'l': '1'
    }

    for i in range(len(domain_name)):
        if domain_name[i] in homoglyphs:
            typos.add(domain_name[:i] + homoglyphs[domain_name[i]] + domain_name[i + 1:] + '.' + extension)

    # Exclude the original domain
    typos.discard(domain)
    
    return list(typos)

# Function to fetch website content with enhanced error handling
def fetch_website_content(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)  # verify=False to ignore SSL errors
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Remove script and style elements
            for script_or_style in soup(['script', 'style']):
                script_or_style.decompose()
            return soup.get_text()
    except requests.RequestException:
        return None
    except UnicodeDecodeError:
        return response.content.decode('utf-8', errors='replace')

# Function to calculate similarity using TF-IDF cosine similarity
def calculate_similarity(content1, content2):
    vectorizer = TfidfVectorizer().fit_transform([content1, content2])
    vectors = vectorizer.toarray()
    cosine_sim = cosine_similarity(vectors)
    return cosine_sim[0][1] * 100  # Convert to percentage

# Function to get geolocation of an IP address using ipwhois
def get_geolocation(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        country = results['asn_country_code']
        return get_countries()[country]
    except Exception:
        return None

# Function to check if a domain exists and if it redirects
def check_domain(domain):
    try:
        response = requests.get(domain, timeout=10, verify=False)
        if response.status_code == 200:
            return response.url
    except requests.RequestException:
        return None

# Function to check WHOIS information
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception:
        return None

# Function to check SSL certificate
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        conn.close()
        return ssl_info
    except Exception:
        return None

# Function to check MX records
def get_mx_records(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10.0
        resolver.timeout = 10.0
        answers = resolver.resolve(domain, 'MX')
        mx_records = [answer.exchange.to_text() for answer in answers]
        return mx_records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return []

# Function to get IP address of a domain
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

# Main function to detect typosquatting
def detect_typosquatting(original_domain, threshold):
    original_domain_with_scheme = f"http://{original_domain}"
    original_content = fetch_website_content(original_domain_with_scheme)
    if not original_content:
        original_domain_with_scheme = f"https://{original_domain}"
        original_content = fetch_website_content(original_domain_with_scheme)
    if not original_content:
        print(Fore.RED + f"Failed to fetch content from {original_domain}")
        return

    typo_domains = generate_typos(original_domain)
    original_ip = get_ip(original_domain)
    if not original_ip:
        print(Fore.RED + f"Failed to fetch IP address for {original_domain}")
        return
    
    original_location = get_geolocation(original_ip)
    original_whois = get_whois_info(original_domain)
    original_ssl = get_ssl_info(original_domain)
    original_mx_records = get_mx_records(original_domain)

    for typo in typo_domains:
        typo_domain = f"http://{typo}"
        redirect_url = check_domain(typo_domain)

        # Inform user about defensive acquisition even if redirected
        if redirect_url and original_domain in redirect_url:
            message = f"Domain {typo_domain} redirects to the original domain {original_domain}, likely acquired defensively."
            print(Fore.GREEN + message)
            if args.verbose:
                print(Fore.WHITE + f"Checking domain: {typo_domain}")
            continue  # Skip further processing for this typo

        typo_ip = get_ip(typo)
        typo_location = get_geolocation(typo_ip) if typo_ip else None
        typo_content = fetch_website_content(redirect_url)
        typo_whois = get_whois_info(typo)
        typo_ssl = get_ssl_info(typo)
        typo_mx_records = get_mx_records(typo)
        
        if typo_content:
            similarity_score = calculate_similarity(original_content, typo_content)
            if similarity_score > threshold:
                print(Fore.RED + f"Possible typosquatting detected for domain: {typo_domain}")
                print(Fore.GREEN + f"IP Address: {typo_ip}")
                print(Fore.CYAN + f"Origin: {typo_location}")
                print(Fore.YELLOW + f"Redirected to: {redirect_url}")
                print(Fore.WHITE + f"Content Similarity Score: {similarity_score:.2f}%")
                if args.verbose:
                    if typo_whois and original_whois:
                        print(Fore.MAGENTA + f"WHOIS Info - Original: {original_whois}, Typo: {typo_whois}")
                    if typo_ssl and original_ssl:
                        print(Fore.BLUE + f"SSL Info - Original: {original_ssl}, Typo: {typo_ssl}")
                    if typo_mx_records and original_mx_records:
                        print(Fore.YELLOW + f"MX Records - Original: {original_mx_records}, Typo: {typo_mx_records}")
            if args.verbose:
                print(Fore.WHITE + f"Checking domain: {typo_domain}")
                print(Fore.WHITE + f"Content similarity score with {original_domain}: {similarity_score:.2f}%")
        else:
            if args.verbose:
                print(Fore.RED + f"Failed to fetch content from {typo_domain}")

# Main script entry
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect typosquatting domains.")
    parser.add_argument("domain", help="The original domain to check for typosquatting.")
    parser.add_argument("-t", "--threshold", type=float, default=70.0, help="The content similarity threshold for detecting typosquatting.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity.")
    args = parser.parse_args()
    
    detect_typosquatting(args.domain, args.threshold)
