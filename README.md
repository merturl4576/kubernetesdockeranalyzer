# 🔒 Container Hardening Analyzer

This project helps you **analyze Dockerfiles and Kubernetes YAML files** for security problems. It also allows you to **fix some issues**, **get AI (GPT) suggestions**, and **export the results** in multiple formats.

---

## 📦 Features

- Detects common security risks:
  - Running as `root`
  - Using `latest` image tags
  - Passwords in `ENV`
  - Bad Kubernetes settings
  - More...
- GPT (AI) support for smart recommendations
- Risk score (0–10) with color indicator:
  - 🟢 Safe
  - 🟡 Medium Risk
  - 🔴 Dangerous
- Export results as:
  - CSV
  - TXT
  - PDF
- Export a **fixed** Dockerfile version

---

## 🖥 GUI Overview

- Dark mode modern GUI with `CustomTkinter`
- Easy buttons to:
  - Select files
  - Analyze them
  - Export results
  - Export fixed Dockerfile

---

## 🧠 AI Support (Optional)

You can use OpenAI GPT to get advanced suggestions.  
Add your API key to the `.env` file like this:

```
OPENAI_API_KEY=sk-YOUR_KEY_HERE
```

---

## ⚙️ Installation

```bash
git clone https://github.com/merturl4576/FinalAnalyzerWithEnv.git
cd FinalAnalyzerWithEnv
pip install -r requirements.txt
```

---

## 🚀 How to Run

```bash
python gui.py
```

GUI will open. Select your Dockerfile or YAML file and click **Analyze**.

---

## 📁 File Types Supported

- `.Dockerfile`
- `.yml`, `.yaml`

---

## 📤 Export Options

- After analysis, you can export:
  - Findings (CSV, TXT, PDF)
  - Fixed version of Dockerfile

---

## 🧪 Technologies Used

- Python 3
- CustomTkinter
- OpenAI API
- FPDF
- Object-Oriented Programming (OOP)
- Matplotlib (for risk charts)

---

## 👨‍💻 Developer

Mert Ural – `merturl67@gmail.com`  
Made with 💙 for OOP Python final project (2025)

---


