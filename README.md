# PhishBuddy - URL Phishing Detector

### 1. Clone the repo

### 2. Create a virtual environment

**Using PyCharm:**
- Go to File > Settings > Project > Python Interpreter
- Click the gear icon and select "Add"
- Choose "Virtualenv" and select Python 3.x as base interpreter
- Click "OK"

**Using Terminal:**
```bash
python -m venv .venv
```

### 3. Activate the virtual environment

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

### 5. Run the Flask development server
```bash
python app.py
```
The application will be available at: **http://127.0.0.1:5000/**

### 6. Run PyTest

**Run all tests:**
```bash
python -m pytest tests/test_phish_detector.py -v
```

**Run specific test class:**
```bash
python -m pytest tests/test_phish_detector.py::{TestClassName} -v
```

**Run with logging output:**
```bash
python -m pytest tests/test_phish_detector.py -v -s
```

**Save test results to text file (Windows PowerShell):**
```powershell
python -m pytest tests/test_phish_detector.py -v | Out-File -Encoding UTF8 tests/results/test_results.txt
```

**Save test results to text file (Mac/Linux):**
```bash
python -m pytest tests/test_phish_detector.py -v > tests/results/test_results.txt
```
