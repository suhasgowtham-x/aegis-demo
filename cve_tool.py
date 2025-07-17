import requests

def search_cve(keyword):
    url = f"https://cve.circl.lu/api/search/{keyword}"
    response = requests.get(url)

    if response.status_code == 200:
        results = response.json().get("results", [])[:5]  # Get top 5 results
        if not results:
            return f"No CVEs found for '{keyword}'."
        
        output = f"Top CVEs for '{keyword}':\n"
        for item in results:
            output += f"\n🔓 {item['id']}: {item['summary'][:120]}...\n"
        return output
    else:
        return "⚠️ Failed to fetch CVE data. Try again later."
