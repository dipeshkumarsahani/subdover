# Subdover

🚀 **Subdover** is a professional and fast **Subdomain Takeover Scanner**.

### 🧠 Features

- ✅ Scans single or multiple subdomains
- ✅ Identifies vulnerable CNAME takeovers
- ✅ Prevents false positives with wildcard DNS detection
- ✅ Color-coded output with rich fingerprinting
- ✅ Results export to CSV, JSON, or TXT
- ✅ No login/API keys required

---

### 🔧 Installation

```bash
git clone https://github.com/dipeshkumarsahani/subdover.git
cd subdover
pip install -r requirements.txt
```
```
# Scan a single subdomain
python3 subdover.py -s test.example.com

# Scan multiple subdomains from a file
python3 subdover.py -l subs.txt

# Use HTTPS instead of HTTP
python3 subdover.py -l subs.txt --https

# Save results to a custom folder in JSON format
python3 subdover.py -l subs.txt -o output/ --format json

# Increase threads (default is 10)
python3 subdover.py -l subs.txt --threads 25
```
