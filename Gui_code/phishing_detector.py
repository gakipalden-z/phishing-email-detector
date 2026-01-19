import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import re
import os
import json
import hashlib
import subprocess
from datetime import datetime

class LocalActivityLogger:
    # Enhanced logging with authentication, analysis, and incident events
    def __init__(self, log_file="activity.log"):
        self.log_file = log_file
    
    def log_entry(self, timestamp, event_type, user, role=None, risk_score=None, risk_level=None, details=None):
        # Log events: login, analysis, incident
        entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "user": user,
            "role": role,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "details": details
        }
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"Logging error: {e}")
    
    def get_logs(self):
        # Retrieve all log entries
        logs = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r") as f:
                    for line in f:
                        if line.strip():
                            logs.append(json.loads(line))
            except Exception as e:
                print(f"Error reading logs: {e}")
        return logs
    
    def get_statistics(self):
        # Calculate metrics from logs
        logs = self.get_logs()
        total_analyzed = sum(1 for log in logs if log.get("event_type") == "Email Analysis")
        high_risk_count = sum(1 for log in logs if log.get("event_type") == "Email Analysis" and log.get("risk_level") == "High Risk")
        incidents = sum(1 for log in logs if log.get("event_type") == "Security Incident")
        last_analysis = None
        for log in reversed(logs):
            if log.get("event_type") == "Email Analysis":
                last_analysis = log.get("timestamp")
                break
        return {
            "total_analyzed": total_analyzed,
            "high_risk_count": high_risk_count,
            "incidents": incidents,
            "last_analysis": last_analysis
        }
    
    def get_incidents(self):
        # Retrieve security incidents only
        logs = self.get_logs()
        return [log for log in logs if log.get("event_type") == "Security Incident"]
    
    def get_login_attempts(self):
        # Retrieve login attempts
        logs = self.get_logs()
        return [log for log in logs if log.get("event_type") in ["Login Success", "Login Failed"]]

class CodeSecurityAnalyzer:
    # Integration of Bandit and Flake8 for code security analysis
    def __init__(self, logger):
        self.logger = logger
        self.scan_results = {}
    
    def check_tool_installed(self, tool_name):
        # Check if Bandit or Flake8 is installed
        try:
            subprocess.run(["python", "-m", tool_name, "--version"], capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def run_bandit_scan(self, file_path, username, user_role):
        # Run Bandit security scan on Python file
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not self.check_tool_installed("bandit"):
            self.logger.log_entry(timestamp, "Security Scan", username, user_role, details="Bandit not installed")
            return {"status": "error", "message": "Bandit not installed. Install with: pip install bandit"}
        
        try:
            result = subprocess.run(
                ["python", "-m", "bandit", "-f", "json", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            scan_data = json.loads(result.stdout)
            issues = scan_data.get("results", [])
            severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            
            for issue in issues:
                severity = issue.get("severity", "LOW")
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            risk_score = min((severity_count.get("HIGH", 0) * 30 + severity_count.get("MEDIUM", 0) * 15 + severity_count.get("LOW", 0) * 5), 100)
            
            self.logger.log_entry(
                timestamp, "Security Scan", username, user_role, risk_score, 
                "High Risk" if risk_score >= 70 else "Medium Risk" if risk_score >= 40 else "Low Risk",
                f"Bandit: {len(issues)} issues found"
            )
            
            return {
                "status": "success",
                "tool": "Bandit",
                "file": file_path,
                "total_issues": len(issues),
                "severity": severity_count,
                "risk_score": risk_score,
                "issues": issues
            }
        except subprocess.TimeoutExpired:
            self.logger.log_entry(timestamp, "Security Scan", username, user_role, details="Bandit scan timeout")
            return {"status": "error", "message": "Bandit scan timed out"}
        except json.JSONDecodeError:
            self.logger.log_entry(timestamp, "Security Scan", username, user_role, details="Bandit JSON parse error")
            return {"status": "error", "message": "Error parsing Bandit results"}
        except Exception as e:
            self.logger.log_entry(timestamp, "Security Scan", username, user_role, details=f"Bandit error: {str(e)}")
            return {"status": "error", "message": f"Bandit scan failed: {str(e)}"}

class LoginWindow:
    # Standalone login window for authentication
    def __init__(self, parent=None):
        self.authenticated_user = None
        self.authenticated_role = None
        
        self.login_window = tk.Tk() if parent is None else tk.Toplevel(parent)
        self.login_window.title("Phishing Detector - Login")
        self.login_window.geometry("350x250")
        self.login_window.resizable(False, False)
        self.login_window.grab_set()
        
        # Credentials
        self.valid_users = {
            "admin": {"password": "admin123", "role": "admin"},
            "user": {"password": "user123", "role": "user"}
        }
        
        self.logger = LocalActivityLogger()
        self.build_ui()
    
    def build_ui(self):
        # Build login form UI
        title = tk.Label(self.login_window, text="Phishing Email Detector", font=("Arial", 14, "bold"), fg="#1976D2")
        title.pack(pady=15)
        
        subtitle = tk.Label(self.login_window, text="DevSecOps Demo", font=("Arial", 9), fg="#666")
        subtitle.pack()
        
        # Username
        tk.Label(self.login_window, text="Username:", font=("Arial", 10)).pack(pady=(15, 5), anchor="w", padx=20)
        self.username_entry = tk.Entry(self.login_window, font=("Arial", 10), width=25)
        self.username_entry.pack(padx=20, pady=5)
        self.username_entry.bind("<Return>", lambda e: self.login())
        
        # Password
        tk.Label(self.login_window, text="Password:", font=("Arial", 10)).pack(pady=(10, 5), anchor="w", padx=20)
        self.password_entry = tk.Entry(self.login_window, font=("Arial", 10), width=25, show="*")
        self.password_entry.pack(padx=20, pady=5)
        self.password_entry.bind("<Return>", lambda e: self.login())
        
        # Login button
        login_btn = tk.Button(self.login_window, text="Login", command=self.login, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), width=25)
        login_btn.pack(pady=20)
        
        # Demo credentials hint
        hint = tk.Label(self.login_window, text="Demo: admin/admin123 or user/user123", font=("Arial", 8), fg="#999")
        hint.pack(pady=5)
    
    def login(self):
        # Validate login credentials
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            self.logger.log_entry(timestamp, "Login Failed", username, role="unknown", details="Empty credentials")
            return
        
        if username in self.valid_users:
            creds = self.valid_users[username]
            if creds["password"] == password:
                self.authenticated_user = username
                self.authenticated_role = creds["role"]
                self.logger.log_entry(timestamp, "Login Success", username, role=creds["role"])
                self.login_window.destroy()
                return
        
        messagebox.showerror("Error", "Invalid username or password")
        self.logger.log_entry(timestamp, "Login Failed", username, role="unknown", details="Invalid credentials")
    
    def get_credentials(self):
        # Return authenticated user and role after login
        self.login_window.mainloop()
        return self.authenticated_user, self.authenticated_role


class PhishingDetector:
    # Main application with RBAC, logging, and incident response
    def __init__(self, root, username, role):
        self.root = root
        self.root.title("Phishing Email Detector - Educational Demo")
        self.root.geometry("950x900")
        self.root.resizable(True, True)
        self.keywords = self.load_keywords()
        self.logger = LocalActivityLogger()
        self.current_user = username
        self.user_role = role
        self.analysis_state = "Idle"
        
        # Initialize code security analyzer
        self.code_analyzer = CodeSecurityAnalyzer(self.logger)
        
        # Metrics tracking
        self.total_emails_analyzed = 0
        self.high_risk_emails = 0
        self.incidents_triggered = 0
        
        # Top information bar
        self.create_info_bar()
        
        # Status label
        self.create_status_bar()
        
        # Input section
        input_label = tk.Label(self.root, text="Paste email content below:", font=("Arial", 10, "bold"))
        input_label.pack(pady=5, padx=10, anchor="w")

        self.email_input = scrolledtext.ScrolledText(self.root, height=8, width=100, wrap=tk.WORD, font=("Arial", 9))
        self.email_input.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        # Button frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10, padx=10, fill=tk.X)
        
        analyze_btn = tk.Button(button_frame, text="Analyze Email", command=self.analyze, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), height=2, cursor="hand2")
        analyze_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Admin-only buttons
        self.view_logs_btn = tk.Button(button_frame, text="View Logs (Admin)", command=self.view_logs, bg="#2196F3", fg="white", font=("Arial", 9), cursor="hand2")
        self.view_logs_btn.pack(side=tk.LEFT, padx=5)
        
        self.view_incidents_btn = tk.Button(button_frame, text="View Incidents (Admin)", command=self.view_incidents, bg="#D32F2F", fg="white", font=("Arial", 9), cursor="hand2")
        self.view_incidents_btn.pack(side=tk.LEFT, padx=5)
        
        self.metrics_btn = tk.Button(button_frame, text="Metrics Dashboard (Admin)", command=self.show_metrics, bg="#7B1FA2", fg="white", font=("Arial", 9), cursor="hand2")
        self.metrics_btn.pack(side=tk.LEFT, padx=5)
        
        self.bandit_btn = tk.Button(button_frame, text="Security Scan (Bandit)", command=self.run_bandit, bg="#FF6F00", fg="white", font=("Arial", 9), cursor="hand2")
        self.bandit_btn.pack(side=tk.LEFT, padx=5)
        
        # Enforce RBAC visibility
        self.enforce_rbac()

        output_label = tk.Label(self.root, text="Analysis Results:", font=("Arial", 10, "bold"))
        output_label.pack(pady=5, padx=10, anchor="w")

        self.output_text = scrolledtext.ScrolledText(self.root, height=12, width=100, wrap=tk.WORD, state=tk.DISABLED, font=("Arial", 9))
        self.output_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

        # Configure text tags for output
        self.output_text.tag_config("low_risk", foreground="green", font=("Arial", 9, "bold"))
        self.output_text.tag_config("medium_risk", foreground="orange", font=("Arial", 9, "bold"))
        self.output_text.tag_config("high_risk", foreground="red", font=("Arial", 9, "bold"))
        self.output_text.tag_config("normal", foreground="black")
        self.output_text.tag_config("header", foreground="blue", font=("Arial", 9, "bold"))
        self.output_text.tag_config("metric", foreground="darkblue", font=("Arial", 9))
        self.output_text.tag_config("warning", foreground="red", font=("Arial", 9, "bold"))
    
    def enforce_rbac(self):
        # Disable admin buttons for non-admin users
        if self.user_role != "admin":
            self.view_logs_btn.config(state=tk.DISABLED)
            self.view_incidents_btn.config(state=tk.DISABLED)
            self.metrics_btn.config(state=tk.DISABLED)
    
    def create_info_bar(self):
        # Top information bar with app name and user info
        info_frame = tk.Frame(self.root, bg="#E3F2FD", height=50)
        info_frame.pack(fill=tk.X, padx=0, pady=0)
        
        app_label = tk.Label(info_frame, text="Phishing Email Detector - DevSecOps Edition", font=("Arial", 12, "bold"), bg="#E3F2FD")
        app_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        user_label = tk.Label(info_frame, text=f"Logged in as: {self.current_user} ({self.user_role})", font=("Arial", 10), bg="#E3F2FD", fg="#1976D2")
        user_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        
    
    def create_status_bar(self):
        # Status bar showing current analysis state
        status_frame = tk.Frame(self.root, bg="#F5F5F5", height=30)
        status_frame.pack(fill=tk.X, padx=0, pady=0)
        
        tk.Label(status_frame, text="Status:", font=("Arial", 9, "bold"), bg="#F5F5F5").pack(side=tk.LEFT, padx=10, pady=3)
        
        self.status_label = tk.Label(status_frame, text="Idle", font=("Arial", 9), bg="#F5F5F5", fg="#4CAF50")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=3)
        
        self.role_label = tk.Label(status_frame, text="Role: User", font=("Arial", 9), bg="#F5F5F5", fg="#FF9800")
        self.role_label.pack(side=tk.RIGHT, padx=10, pady=3)
    
    def toggle_role(self):
        # Toggle between User and Admin roles
        if self.user_role == "user":
            self.user_role = "admin"
            messagebox.showinfo("Role Changed", "Switched to Admin role (read-only mode)")
        else:
            self.user_role = "user"
            messagebox.showinfo("Role Changed", "Switched to User role")
        self.role_label.config(text=f"Role: {self.user_role.capitalize()}")
    
    def view_logs(self):
        # Admin function to view logs and statistics
        if self.user_role != "admin":
            messagebox.showwarning("Access Denied", "Only Admin can view logs.")
            return
        
        logs = self.logger.get_logs()
        stats = self.logger.get_statistics()
        
        log_window = tk.Toplevel(self.root)
        log_window.title("Activity Logs - Admin View")
        log_window.geometry("700x500")
        
        # Statistics frame
        stats_text = tk.Label(log_window, text=f"Emails: {stats['total_analyzed']} | High Risk: {stats['high_risk_count']} | Incidents: {stats['incidents']}", font=("Arial", 10, "bold"))
        stats_text.pack(pady=10)
        
        # Logs display
        log_display = scrolledtext.ScrolledText(log_window, height=25, width=80, wrap=tk.WORD, font=("Arial", 8), state=tk.DISABLED)
        log_display.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        
        log_display.config(state=tk.NORMAL)
        log_display.insert(tk.END, "Activity Log (Most Recent First):\n\n")
        for log in reversed(logs[-50:]):
            event = log.get('event_type', 'N/A')
            user = log.get('user', 'N/A')
            role = log.get('role', 'N/A')
            timestamp = log.get('timestamp', 'N/A')
            log_entry = f"[{timestamp}] {event} | User: {user} ({role})\n"
            log_display.insert(tk.END, log_entry)
        log_display.config(state=tk.DISABLED)

    
    def view_incidents(self):
        # Admin-only window to view security incidents
        if self.user_role != "admin":
            messagebox.showwarning("Access Denied", "Only Admin can view incidents.")
            return
        
        incidents = self.logger.get_incidents()
        
        incident_window = tk.Toplevel(self.root)
        incident_window.title("Security Incidents - Admin View")
        incident_window.geometry("750x500")
        
        # Header
        header = tk.Label(incident_window, text=f"Total Incidents: {len(incidents)}", font=("Arial", 11, "bold"), fg="#D32F2F")
        header.pack(pady=10)
        
        # Incident display
        incident_display = scrolledtext.ScrolledText(incident_window, height=25, width=90, wrap=tk.WORD, font=("Arial", 9), state=tk.DISABLED)
        incident_display.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        
        incident_display.config(state=tk.NORMAL)
        if not incidents:
            incident_display.insert(tk.END, "No security incidents recorded.\n")
        else:
            for incident in reversed(incidents[-50:]):
                timestamp = incident.get('timestamp', 'N/A')
                user = incident.get('user', 'N/A')
                score = incident.get('risk_score', 'N/A')
                details = incident.get('details', 'N/A')
                incident_text = f"[{timestamp}] User: {user} | Score: {score}/100 | Details: {details}\n"
                incident_display.insert(tk.END, incident_text)
        incident_display.config(state=tk.DISABLED)
    
    def show_metrics(self):
        # Admin-only metrics dashboard
        if self.user_role != "admin":
            messagebox.showwarning("Access Denied", "Only Admin can view metrics.")
            return
        
        stats = self.logger.get_statistics()
        
        metrics_window = tk.Toplevel(self.root)
        metrics_window.title("Metrics Dashboard - Admin")
        metrics_window.geometry("500x350")
        metrics_window.config(bg="#F5F5F5")
        
        # Title
        title = tk.Label(metrics_window, text="Security Metrics Dashboard", font=("Arial", 14, "bold"), bg="#F5F5F5", fg="#1976D2")
        title.pack(pady=15)
        
        # Metrics frame
        metrics_frame = tk.Frame(metrics_window, bg="white", relief=tk.SUNKEN)
        metrics_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        # Total Emails
        tk.Label(metrics_frame, text="Total Emails Analyzed", font=("Arial", 11, "bold"), bg="white").pack(pady=(15, 5), anchor="w", padx=15)
        tk.Label(metrics_frame, text=str(stats['total_analyzed']), font=("Arial", 24, "bold"), fg="#4CAF50", bg="white").pack(anchor="w", padx=15)
        
        # High Risk Count
        tk.Label(metrics_frame, text="High Risk Detections", font=("Arial", 11, "bold"), bg="white").pack(pady=(15, 5), anchor="w", padx=15)
        tk.Label(metrics_frame, text=str(stats['high_risk_count']), font=("Arial", 24, "bold"), fg="#F44336", bg="white").pack(anchor="w", padx=15)
        
        # Incidents Triggered
        tk.Label(metrics_frame, text="Security Incidents (Score >= 70)", font=("Arial", 11, "bold"), bg="white").pack(pady=(15, 5), anchor="w", padx=15)
        tk.Label(metrics_frame, text=str(stats['incidents']), font=("Arial", 24, "bold"), fg="#D32F2F", bg="white").pack(anchor="w", padx=15)
        
        # Last Analysis
        last_analysis = stats['last_analysis'] if stats['last_analysis'] else "Never"
        tk.Label(metrics_frame, text="Last Analysis", font=("Arial", 11, "bold"), bg="white").pack(pady=(15, 5), anchor="w", padx=15)
        tk.Label(metrics_frame, text=last_analysis, font=("Arial", 11), bg="white").pack(anchor="w", padx=15)
    
    def load_keywords(self):
        # Load phishing keywords from text file
        keyword_file = os.path.join(os.path.dirname(__file__), "phishing_keywords.txt")
        if not os.path.exists(keyword_file):
            messagebox.showerror("Error", f"Keyword database not found: {keyword_file}")
            return []
        
        try:
            with open(keyword_file, "r") as f:
                keywords = [line.strip().lower() for line in f if line.strip()]
            return keywords
        except Exception as e:
            messagebox.showerror("Error", f"Error reading keywords: {e}")
            return []

    def analyze(self):
        email = self.email_input.get("1.0", tk.END).strip()

        if not email:
            messagebox.showerror("Error", "Please paste email content to analyze.")
            return

        self.update_status("Analyzing")
        self.root.update()
        
        results = self.detect_phishing(email)
        
        # Log the analysis event
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.logger.log_entry(timestamp, "Email Analysis", self.current_user, self.user_role, results["score"], results["level"])
        
        # Check if incident triggered (score >= 70)
        if results["score"] >= 70:
            self.incidents_triggered += 1
            incident_detail = f"Risk score {results['score']}/100 - High risk email detected"
            self.logger.log_entry(timestamp, "Security Incident", self.current_user, self.user_role, results["score"], results["level"], incident_detail)
            messagebox.showwarning("Security Alert", f"INCIDENT TRIGGERED!\nRisk Score: {results['score']}/100\nThis email has been flagged as a security incident.")
        
        # Update metrics
        self.total_emails_analyzed += 1
        if results["level"] == "High Risk":
            self.high_risk_emails += 1
        
        self.display_results(results)
        self.update_status("Completed")

    def detect_phishing(self, email):
        keyword_matches = self.find_keywords(email, self.keywords)
        suspicious_urls = self.find_suspicious_urls(email)
        sensitive_info = self.detect_sensitive_requests(email)

        keyword_score, url_score, sensitive_score = self.calculate_weighted_scores(keyword_matches, suspicious_urls, sensitive_info)
        total_score = min(keyword_score + url_score + sensitive_score, 100)

        return {
            "score": total_score,
            "level": self.get_risk_level(total_score),
            "keywords": keyword_matches,
            "urls": suspicious_urls,
            "sensitive": sensitive_info,
            "keyword_score": keyword_score,
            "url_score": url_score,
            "sensitive_score": sensitive_score
        }
    
    def calculate_weighted_scores(self, keywords, urls, sensitive):
        # Calculate individual component scores with weights
        keyword_score = 0
        for keyword in keywords:
            if isinstance(keyword, dict):
                keyword_score += 15 if keyword.get("risk") == "high" else 10
            else:
                keyword_score += 12
        keyword_score = min(keyword_score, 40)
        
        url_score = 0
        for url_info in urls:
            if isinstance(url_info, dict):
                url_score += 20 if url_info.get("risk_level") == "high" else 15
            else:
                url_score += 15
        url_score = min(url_score, 35)
        
        sensitive_score = 0
        for request in sensitive:
            if isinstance(request, dict):
                sensitive_score += 35 if request.get("risk") == "critical" else 25
            else:
                sensitive_score += 25
        sensitive_score = min(sensitive_score, 25)
        
        return keyword_score, url_score, sensitive_score
    
    def find_keywords(self, text, keywords):
        # Find phishing keywords in email text
        found = []
        text_lower = text.lower()
        high_risk_keywords = ["verify", "urgent", "update", "confirm", "password", "login", "account", "reset password"]
        
        for keyword in keywords:
            if keyword in text_lower:
                found.append({"keyword": keyword, "risk": "high" if keyword in high_risk_keywords else "medium"})
        
        unique_found = {item["keyword"]: item for item in found}.values()
        return list(unique_found)

    def find_suspicious_urls(self, text):
        # Detect suspicious URL patterns
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, text)
        suspicious = []

        for url in urls:
            issues = []
            risk_level = "low"

            if url.startswith("http://"):
                issues.append("Non-secure HTTP connection")
                risk_level = "high"

            if re.search(r'bit\.ly|tinyurl|short\.link|ow\.ly|goo\.gl|short\.url', url, re.IGNORECASE):
                issues.append("URL shortener detected (hides true destination)")
                risk_level = "high"

            if re.search(r'(login|account|verify|secure|update|confirm|password|reset)[-._]', url, re.IGNORECASE):
                issues.append("Suspicious credential-themed domain pattern")
                risk_level = "high"

            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                issues.append("IP-based URL (unusual, potential spoofing)")
                risk_level = "high"

            if url.count('.') > 3:
                issues.append("Excessive subdomains (possible phishing)")
                risk_level = "medium"

            if re.search(r'(g00gle|amaz0n|paypa1|m1crosoft)', url, re.IGNORECASE):
                issues.append("Potential homograph attack detected")
                risk_level = "high"

            if issues:
                suspicious.append({"url": url, "issues": issues, "risk_level": risk_level})

        return suspicious

    def detect_sensitive_requests(self, text):
        # Detect requests for sensitive information
        text_lower = text.lower()
        requests = []

        if re.search(r'\b(password|passwd|pwd|passphrase)\b', text_lower):
            requests.append({"request": "Password requested", "risk": "critical"})

        if re.search(r'(credit\s*card|card\s*number|cvv|cvc|ssn|social\s*security|bank\s*account|routing\s*number)', text_lower):
            requests.append({"request": "Credit card or SSN requested", "risk": "critical"})

        if re.search(r'(confirm.*identity|verify.*account|validate.*info|re-enter.*password|re-authenticate)', text_lower):
            requests.append({"request": "Identity or credential verification requested", "risk": "critical"})

        if re.search(r'(banking|account|payment)\s*(information|details|credentials)', text_lower):
            requests.append({"request": "Banking or payment information requested", "risk": "critical"})

        if re.search(r'(date\s*of\s*birth|phone\s*number|address|drivers?\s*license|passport)', text_lower):
            requests.append({"request": "Personal identification information requested", "risk": "high"})

        if re.search(r'(2fa|two.?factor|mfa|multi.?factor|authentication code|verification code)', text_lower):
            requests.append({"request": "2FA/MFA code requested (unusual)", "risk": "critical"})

        return requests

    def get_risk_level(self, score):
        # Classify risk level based on score
        if score < 30:
            return "Low Risk"
        elif score < 60:
            return "Medium Risk"
        else:
            return "High Risk"
    
    def update_status(self, state):
        # Update analysis status
        self.analysis_state = state
        color = "#4CAF50" if state == "Completed" else "#FF9800" if state == "Analyzing" else "#666666"
        self.status_label.config(text=state, fg=color)

    def display_results(self, results):
        # Display analysis results with metrics and incident response
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)

        score = results["score"]
        level = results["level"]

        tag = "low_risk" if "Low" in level else "medium_risk" if "Medium" in level else "high_risk"

        self.output_text.insert(tk.END, "=== ANALYSIS RESULTS ===\n", "header")
        self.output_text.insert(tk.END, f"Risk Score: {score}/100\n")
        self.output_text.insert(tk.END, f"Risk Level: {level}\n", tag)
        self.output_text.insert(tk.END, "\n")
        
        # Display weighted scores breakdown
        self.output_text.insert(tk.END, "Score Breakdown:\n", "metric")
        self.output_text.insert(tk.END, f"  - Keyword Score: {results['keyword_score']}/40\n")
        self.output_text.insert(tk.END, f"  - URL Score: {results['url_score']}/35\n")
        self.output_text.insert(tk.END, f"  - Sensitive Info Score: {results['sensitive_score']}/25\n")
        self.output_text.insert(tk.END, "\n")
        
        # Display metrics panel
        self.output_text.insert(tk.END, "Detection Summary:\n", "metric")
        self.output_text.insert(tk.END, f"  - Keywords Detected: {len(results['keywords'])}\n")
        self.output_text.insert(tk.END, f"  - Suspicious URLs: {len(results['urls'])}\n")
        self.output_text.insert(tk.END, f"  - Sensitive Info Requests: {len(results['sensitive'])}\n")
        self.output_text.insert(tk.END, f"  - Total Emails Analyzed: {self.total_emails_analyzed}\n")
        self.output_text.insert(tk.END, f"  - High Risk Count: {self.high_risk_emails}\n")
        self.output_text.insert(tk.END, f"  - Incidents Triggered: {self.incidents_triggered}\n")
        self.output_text.insert(tk.END, "\n")

        if results["keywords"]:
            self.output_text.insert(tk.END, "Detected Phishing Keywords:\n", "header")
            for keyword in sorted(results["keywords"], key=lambda x: x.get("keyword", x) if isinstance(x, dict) else x):
                if isinstance(keyword, dict):
                    risk_color = "high_risk" if keyword.get("risk") == "high" else "medium_risk"
                    self.output_text.insert(tk.END, f"  - {keyword['keyword']} ({keyword.get('risk', 'medium').upper()})\n", risk_color)
                else:
                    self.output_text.insert(tk.END, f"  - {keyword}\n")
            self.output_text.insert(tk.END, "\n")

        if results["urls"]:
            self.output_text.insert(tk.END, "Suspicious URLs Detected:\n", "header")
            for url_info in results["urls"]:
                self.output_text.insert(tk.END, f"  - {url_info['url']}\n")
                for issue in url_info["issues"]:
                    self.output_text.insert(tk.END, f"    - {issue}\n")
            self.output_text.insert(tk.END, "\n")

        if results["sensitive"]:
            self.output_text.insert(tk.END, "Sensitive Information Requests:\n", "header")
            for request in results["sensitive"]:
                if isinstance(request, dict):
                    risk_color = "high_risk" if request.get("risk") == "critical" else "medium_risk"
                    self.output_text.insert(tk.END, f"  - {request['request']} ({request.get('risk', 'high').upper()})\n", risk_color)
                else:
                    self.output_text.insert(tk.END, f"  - {request}\n")
            self.output_text.insert(tk.END, "\n")

        if not results["keywords"] and not results["urls"] and not results["sensitive"]:
            self.output_text.insert(tk.END, "No phishing indicators detected. Email appears safe.\n", "low_risk")
        
        # Incident response simulation for high-risk emails
        if results["level"] == "High Risk" or results["score"] >= 70:
            self.output_text.insert(tk.END, "\n")
            self.output_text.insert(tk.END, "SECURITY INCIDENT: High-Risk Email Detected!\n", "warning")
            self.output_text.insert(tk.END, "Recommended Actions:\n", "warning")
            self.output_text.insert(tk.END, "  - Do not click any links in this email\n")
            self.output_text.insert(tk.END, "  - Do not download any attachments\n")
            self.output_text.insert(tk.END, "  - Do not reply with sensitive information\n")
            self.output_text.insert(tk.END, "  - Report email to IT security team\n")
            self.output_text.insert(tk.END, "  - Mark as spam/phishing\n")

        self.output_text.config(state=tk.DISABLED)

    def run_bandit(self):
        # Open file dialog and run Bandit security scan
        file_path = filedialog.askopenfilename(
            title="Select Python file to scan with Bandit",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        self.update_status("Scanning with Bandit")
        self.root.update()
        
        results = self.code_analyzer.run_bandit_scan(file_path, self.current_user, self.user_role)
        self.display_security_scan_results(results)
        self.update_status("Completed")
    
    def display_security_scan_results(self, results):
        # Display security scan results in output area
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        
        if results["status"] == "error":
            self.output_text.insert(tk.END, "SCAN ERROR\n", "header")
            self.output_text.insert(tk.END, results["message"] + "\n", "warning")
            self.output_text.insert(tk.END, "\nInstallation Instructions:\n", "header")
            self.output_text.insert(tk.END, "Run: pip install bandit\n")
        else:
            tool = results["tool"]
            file_path = results["file"]
            total_issues = results["total_issues"]
            risk_score = results["risk_score"]
            severity = results["severity"]
            
            self.output_text.insert(tk.END, f"=== {tool.upper()} SECURITY SCAN RESULTS ===\n", "header")
            self.output_text.insert(tk.END, f"File: {file_path}\n")
            self.output_text.insert(tk.END, f"Risk Score: {risk_score}/100\n")
            self.output_text.insert(tk.END, f"Total Issues: {total_issues}\n", "metric")
            
            # Severity breakdown
            self.output_text.insert(tk.END, f"  - HIGH Severity: {severity.get('HIGH', 0)}\n")
            self.output_text.insert(tk.END, f"  - MEDIUM Severity: {severity.get('MEDIUM', 0)}\n")
            self.output_text.insert(tk.END, f"  - LOW Severity: {severity.get('LOW', 0)}\n")
            
            self.output_text.insert(tk.END, "\n")
            
            # Display issues
            if results["issues"]:
                self.output_text.insert(tk.END, "Issues Found:\n", "header")
                for idx, issue in enumerate(results["issues"], 1):
                    if isinstance(issue, dict):
                        severity_level = issue.get("severity", "MEDIUM")
                        issue_type = issue.get("issue_text", "Unknown issue")
                        line_no = issue.get("line_number", "?")
                        severity_tag = "high_risk" if severity_level == "HIGH" else "medium_risk" if severity_level == "MEDIUM" else "low_risk"
                        self.output_text.insert(tk.END, f"{idx}. [{severity_level}] Line {line_no}: {issue_type}\n", severity_tag)
                        test_id = issue.get("test_id", "")
                        if test_id:
                            self.output_text.insert(tk.END, f"   Test ID: {test_id}\n", "normal")
                    else:
                        # Text-based issue
                        self.output_text.insert(tk.END, f"{idx}. {issue}\n", "normal")
                self.output_text.insert(tk.END, "\n")
            else:
                self.output_text.insert(tk.END, "No issues found! Code is secure.\n", "low_risk")
            
            # Risk summary
            self.output_text.insert(tk.END, "Risk Assessment:\n", "header")
            if risk_score >= 70:
                self.output_text.insert(tk.END, f"Status: HIGH RISK ({risk_score}/100)\n", "high_risk")
                self.output_text.insert(tk.END, "Recommended: Address critical security issues before deployment\n", "warning")
            elif risk_score >= 40:
                self.output_text.insert(tk.END, f"Status: MEDIUM RISK ({risk_score}/100)\n", "medium_risk")
                self.output_text.insert(tk.END, "Recommended: Review and address reported issues\n", "warning")
            else:
                self.output_text.insert(tk.END, f"Status: LOW RISK ({risk_score}/100)\n", "low_risk")
                self.output_text.insert(tk.END, "Recommended: Continue monitoring for updates\n", "normal")
        
        self.output_text.config(state=tk.DISABLED)



def main():
    # Launch login window first, then main application
    login = LoginWindow()
    username, role = login.get_credentials()
    
    if username and role:
        root = tk.Tk()
        app = PhishingDetector(root, username, role)
        root.mainloop()


if __name__ == "__main__":
    main()
