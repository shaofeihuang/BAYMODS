import requests
import argparse
from datetime import datetime

def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()["data"]
    if not data:
        return None
    return data[0]["epss"]

def get_epss_time_series(cve_id):
    """
    Retrieve EPSS time series data (daily) for a CVE from FIRST.org.
    If 'time-series' data is missing, falls back to the latest available score.
    Returns a list (even if only one value).
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}&scope=time-series"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json().get("data", [])

    epss_scores = []
    if data:
        if "time-series" in data[0] and data[0]["time-series"]:
            for entry in data[0]["time-series"]:
                epss_scores.append(entry["epss"])
        elif "epss" in data[0]:
            epss_scores.append(data[0]["epss"])
    return epss_scores

def calculate_lev(epss_scores):
    """
    Calculate LEV from list of EPSS probabilities.
    """
    if not epss_scores:
        return None
    prob_no_exploit = 1.0
    window = len(epss_scores)
    for p in epss_scores:
        if window >= 30:
            weight = 1
        else:
            weight = window / 30
        prob_no_exploit *= (1 - float(p) *  weight)
    return 1 - prob_no_exploit

def get_cvss_score(cve_id, api_key=None):
    """Retrieve CVSS base score from NVD API v2."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    try:
        return data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    except (KeyError, IndexError):
        return None

def check_kev_status(cve_id):
    """Check if CVE is in CISA KEV catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    response.raise_for_status()
    kev_data = response.json()
    for item in kev_data.get("vulnerabilities", []):
        if item.get("cveID", "").upper() == cve_id.upper():
            return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Fetch vulnerability attributes (EPSS, CVSS, KEV) for a CVE ID.")
    parser.add_argument("cve", type=str, help="CVE identifier (e.g. CVE-2023-24236)")
    parser.add_argument("--nvd-api-key", type=str, help="NVD API key (if available)", default=None)
    args = parser.parse_args()

    cve_id = args.cve
    api_key = args.nvd_api_key

    print("--------------------------------------------------------")
    print(f"Vulnerability Scoring for {cve_id}")
    print("Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("--------------------------------------------------------")

    # Retrieve CVSS score
    try:
        cvss_score = get_cvss_score(cve_id, api_key)
        if cvss_score:
            print(f"CVSS v3.1 base score for {cve_id}: {cvss_score}")
        else:
            print(f"CVSS score not found for {cve_id}")
    except requests.HTTPError as err:
        print(f"Error retrieving CVSS score: {err}")

    print("--------------------------------------------------------")

    # Retrieve and display EPSS time series
    epss_scores = get_epss_time_series(cve_id)
    print(f"EPSS time series for {cve_id}: {epss_scores}")
  
    # Display latest EPSS score
    latest_epss = get_epss_score(cve_id)
    if latest_epss:
        print(f"[*] Latest EPSS score for {cve_id}: {latest_epss}")
    else:
        print(f"[*] No latest EPSS score available for {cve_id}")

    print("--------------------------------------------------------")

    # Calculate LEV
    if epss_scores:
        lev_score = calculate_lev(epss_scores)
        print(f"LEV score for {cve_id}: {lev_score:.4f} ({lev_score * 100:.4f}%)")
    else:
        lev_score = None
        print(f"No EPSS time series data available for {cve_id}")

    print("--------------------------------------------------------")

    # Check KEV status
    kev = check_kev_status(cve_id)
    print(f"Is {cve_id} in KEV catalog?: {'Yes' if kev else 'No'}")

    print("--------------------------------------------------------")

    # Compute Exploitation Probability
    try:
        if kev:
            finalprob = 1.0
            print(f"[*] Exploitation Probability for {cve_id} = 1.0 (KEV listed)")
        else:
            if lev_score is not None and (latest_epss is None or lev_score > float(latest_epss)):
                finalprob = lev_score
            elif latest_epss is not None:
                finalprob = float(latest_epss)
            else:
                finalprob = "N/A"
            print(f"[*] Exploitation Probability for {cve_id} = {finalprob:.4f}")
    except Exception as e:
        print(f"Error calculating exploitation probability: {e}")

    print("--------------------------------------------------------")

if __name__ == "__main__":
    main()
