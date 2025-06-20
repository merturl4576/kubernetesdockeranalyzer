import re  #regular expressions
from base_analyzer import BaseAnalyzer
from gpt_modules.gpt_helper import get_gpt_suggestions
from models.finding import Finding
import matplotlib.pyplot as plt
import io
import base64

class DockerfileAnalyzer(BaseAnalyzer):
    def __init__(self, content, use_gpt=False):
        super().__init__(content)     #Call the constructor in the superclass (BaseAnalyzer)
        self.use_gpt = use_gpt

    def analyze(self):
        self.findings.clear()
        self.raw_scores = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        def add_finding(level, message, suggestion):
            self.findings.append(Finding(level, message, suggestion))
            self.raw_scores[level] += 1

        if 'USER root' in self.content:
            add_finding("HIGH", "Runs as root user", "Use non-root user (CIS Docker Benchmark 4.1, OWASP A3)")

        if 'ubuntu:latest' in self.content or 'alpine:latest' in self.content:
            add_finding("MEDIUM", "Uses 'latest' tag", "Use fixed version tag like 'ubuntu:20.04' (OWASP A1)")

        if re.search(r'ENV\s+\w*PASS\w*\s*=\s*.+', self.content):
            add_finding("HIGH", "ENV variable contains possible password", "Avoid using passwords in ENV (OWASP A6)")

        if 'ADD ' in self.content:
            add_finding("LOW", "Using ADD instead of COPY", "Use COPY unless you need ADD features (CIS 4.9)")

        if 'COPY .' in self.content or 'COPY /' in self.content:
            add_finding("MEDIUM", "Copying entire directory", "Use specific files/folders in COPY (CIS 4.10)")

        if 'EXPOSE 80' in self.content:
            add_finding("MEDIUM", "Exposing port 80 without HTTPS", "Consider using EXPOSE 443 (OWASP A5)")

        if 'HEALTHCHECK' not in self.content:
            add_finding("LOW", "No HEALTHCHECK defined", "Define a HEALTHCHECK for better container reliability (OWASP A10)")

        if 'apt-get install' in self.content and '--no-install-recommends' not in self.content:
            add_finding("LOW", "No install optimization", "Use --no-install-recommends to reduce image size (CIS 4.4)")

        if 'rm -rf /var/lib/apt/lists' not in self.content:
            add_finding("LOW", "APT cache not cleaned", "Clean apt cache after install to reduce size (CIS 4.5)")

        if 'apiVersion' in self.content and 'kind: Pod' in self.content:
            if 'securityContext:' not in self.content:
                add_finding("HIGH", "Kubernetes: securityContext block missing", "Define securityContext with proper fields (CIS K8s 5.2.5)")
            else:
                if 'runAsNonRoot: true' not in self.content:
                    add_finding("MEDIUM", "Kubernetes: runAsNonRoot missing", "Set runAsNonRoot: true (CIS K8s 5.2.6)")
                if 'readOnlyRootFilesystem: true' not in self.content:
                    add_finding("MEDIUM", "Kubernetes: readOnlyRootFilesystem missing", "Set readOnlyRootFilesystem: true (CIS K8s 5.2.8)")
                if 'allowPrivilegeEscalation: false' not in self.content:
                    add_finding("MEDIUM", "Kubernetes: allowPrivilegeEscalation missing", "Set allowPrivilegeEscalation: false (CIS K8s 5.2.9)")

        if self.use_gpt:
            self.findings.extend(get_gpt_suggestions(self.content))

        return self.findings

    def generate_fixed(self):
        fixed = self.content

        fixed = fixed.replace('USER root', 'RUN useradd -m appuser\nUSER appuser')
        fixed = fixed.replace('ubuntu:latest', 'ubuntu:20.04')
        fixed = fixed.replace('alpine:latest', 'alpine:3.18')

        # ENV satırında şifre içerdiği düşünülen değişken varsa tamamen sil (geliştirilmiş)
        fixed = re.sub(r'^ENV\s+.*PASS.*=.*$', '', fixed, flags=re.MULTILINE)

        fixed = fixed.replace('ADD . /app', 'COPY ./src /app')
        fixed = re.sub(r'apt-get install(?!.*--no-install-recommends)', 'apt-get install --no-install-recommends', fixed)
        if 'rm -rf /var/lib/apt/lists' not in fixed:
            fixed += '\nRUN rm -rf /var/lib/apt/lists/*'
        if 'HEALTHCHECK' not in fixed:
            fixed += '\nHEALTHCHECK CMD curl --fail http://localhost || exit 1'
        fixed = fixed.replace('EXPOSE 80', 'EXPOSE 443')
        if 'securityContext:' not in fixed and 'apiVersion' in fixed:
            fixed += "\nsecurityContext:\n  runAsNonRoot: true\n  readOnlyRootFilesystem: true\n  allowPrivilegeEscalation: false"

        return fixed

    def get_score_visual(self):
        labels = list(self.raw_scores.keys())
        values = list(self.raw_scores.values())

        fig, ax = plt.subplots()
        ax.bar(labels, values)
        ax.set_title("Risk Level Distribution")
        ax.set_ylabel("Count")

        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        plt.close(fig)
        return img_base64