# Subdover

🚀 **Subdover** is a professional and fast **Subdomain Takeover Scanner** designed for bug bounty hunters and penetration testers.

---

## 🧠 Features

- ✅ Scan single or multiple subdomains
- ✅ Detect vulnerable CNAME-based takeovers
- ✅ Prevent false positives with wildcard DNS detection
- ✅ Color-coded terminal output
- ✅ Export results to CSV, JSON, or TXT
- ✅ No login or API key required

---

## 🔧 Installation

```bash
git clone https://github.com/dipeshkumarsahani/subdover.git
cd subdover
pip install -r requirements.txt
```

▶️ Usage
```
# Scan a single subdomain
python3 subdover.py -s test.example.com

# Scan multiple subdomains from a file
python3 subdover.py -l subs.txt

# Use HTTPS instead of HTTP
python3 subdover.py -l subs.txt --https

# Save results in JSON format to a folder
python3 subdover.py -l subs.txt -o output/ --format json

# Increase thread count (default is 10)
python3 subdover.py -l subs.txt --threads 25
```
---
## 📦 Output
Subdover saves results in timestamped files in your specified format:

- **CSV** – Easy to open in Excel or Google Sheets  
- **JSON** – Great for automation or scripting  
- **TXT** – Human-readable format

---

![image](https://github.com/user-attachments/assets/6788f624-7b10-41dd-9e78-2e9575e25527)

---

## 🧑‍💻 Author

**Dipesh Kumar Sahani**  
🔗 GitHub: [@dipeshkumarsahani](https://github.com/dipeshkumarsahani)<br>
👤 **LinkedIn:** [Dipesh Kumar Sahani](https://www.linkedin.com/in/dipeshkumarsahani) 

---








