# Typosquatting Detection Script

This script is designed to detect potential typosquatting domains for a given target domain. Typosquatting is a form of cybersquatting where attackers register domain names similar to a popular brand or company to divert web traffic, engage in phishing, or sell the domain to the affected party. 

## Features

- **Typo Generation**: Generates potential typos for a given domain using techniques such as omission, swap, insertion, substitution, repetition, and transposition.
- **Domain Existence and Redirection Checking**: Checks if a generated typo domain exists and if it redirects to another domain.
- **Statistical Text Matching**: Compares the content of the original website and the typo website using a statistical text matching algorithm (TF-IDF cosine similarity).
- **Geo-Location**: Finds the geolocation of the IP addresses associated with the original and typo domains.
- **WHOIS and SSL Information**: Retrieves WHOIS and SSL certificate information for the original and typo domains.
- **MX Records**: Retrieves MX records for the original and typo domains.

## Installation

Ensure you have Python installed. The script requires the following Python packages:

- `requests`
- `beautifulsoup4`
- `scikit-learn`
- `python-whois`
- `dnspython`
- `ipwhois`
- `colorama`

Install the required packages using the following command:

```sh
pip install requests beautifulsoup4 scikit-learn python-whois dnspython ipwhois colorama



Usage

Run the script with the target domain as an argument. Use the -v flag for verbose output.

python3 typosquatting-detection.py <target-domain> [-v]


Output

The script will output potential typosquatting domains, along with the following information for each detected domain:

    IP Address
    Geolocation
    Redirection URL
    Content Similarity Score
    WHOIS Information (if verbose mode is enabled)
    SSL Information (if verbose mode is enabled)
    MX Records (if verbose mode is enabled)

Error Handling

The script includes error handling for various scenarios, such as:

    Failed to fetch content from a domain
    Failed to fetch IP address
    DNS resolution errors for MX records

Notes

    The script ignores typos that redirect to the original domain, assuming these are acquired defensively.
    The script uses a threshold of 70% content similarity to flag potential typosquatting domains.
