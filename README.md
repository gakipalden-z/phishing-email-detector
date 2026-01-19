# Phishing Email Detector (DevSecOps Project)

## Overview
This project is a **GUI-based phishing email detection tool** developed as part of **ICT932 – Cybersecurity Testing and Assurance**.  
The application analyses email content using heuristic-based techniques to identify phishing indicators such as suspicious keywords, unsafe URLs, and sensitive information requests.

The project applies **DevSecOps principles** by integrating security checks, code quality analysis, and automated testing into a CI/CD pipeline using GitHub Actions.

---

## Features
- GUI-based phishing email analysis (Python Tkinter)
- Keyword-based phishing detection
- Suspicious URL pattern analysis
- Risk scoring (Low / Medium / High)
- Role-Based Access Control (User & Admin)
- Activity logging (privacy-preserving)
- Incident alert simulation for high-risk emails
- Automated CI/CD pipeline with security scanning

---

## DevSecOps Implementation
This project follows a **shift-left security approach**:

- Security considered during design and development
- Static security analysis using **Bandit**
- Code quality checks using **Flake8**
- Automated testing using **Pytest**
- CI/CD pipeline implemented using **GitHub Actions**
- Non-blocking security scans to reflect real-world DevSecOps practices

Every push to the `main` branch triggers automated security and quality checks.

---

## CI/CD Pipeline
The GitHub Actions pipeline performs:
1. Repository checkout
2. Python environment setup
3. Dependency installation
4. Security scanning with Bandit
5. Linting with Flake8
6. Automated test execution with Pytest

Pipeline status is visible under the **Actions** tab.

---

## Technologies Used
- Python 3.11
- Tkinter (GUI)
- Bandit (Security scanning)
- Flake8 (Linting)
- Pytest (Testing)
- GitHub Actions (CI/CD)

---

## How to Run the Application
1. Clone the repository:
   ```bash
   git clone https://github.com/gakipalden-z/phishing-email-detector.git

---

## Evidence
The following evidence is included in this repository:

- GitHub Actions CI/CD pipeline execution (green success runs)
- Security scanning results using Bandit
- Automated linting and testing results
- GUI application execution screenshots

All screenshots are available in the `screenshots/` directory.

---

## Academic Declaration
This project was developed for academic purposes as part of **ICT932 – Cybersecurity Testing and Assurance**.  
All work presented is original and intended solely for educational evaluation.

