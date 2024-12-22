import requests
import json

API_KEY = 'YOUR API KEY'

def ip_scan(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()

def print_info(ip_info):
    if 'data' in ip_info:
        data = ip_info['data']
        attributes = data.get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        print("\nIP Address:", data.get('id'))
        print("Last Analysis Stats:")
        print("  Malicious:", last_analysis_stats.get('malicious', 0))
        print("  Suspicious:", last_analysis_stats.get('suspicious', 0))
        print("  Harmless:", last_analysis_stats.get('harmless', 0))
        print("  Undetected:", last_analysis_stats.get('undetected', 0))
    else:
        print("Error: No data found or invalid IP address.")
        if 'error' in ip_info:
            print("Error Details:", ip_info['error'])

def main():
    while True:
        ip = input("\nEnter an IP address to scan: ").strip()
        
        try:
            result = ip_scan(ip)
            print_info(result)
        except Exception as e:
            print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
