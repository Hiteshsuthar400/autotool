import os
import subprocess
import shutil
from pathlib import Path

# ------------------ TOOL CATEGORIES ----------------
recon_tools = [
    ("amass", "sudo apt install -y amass"),
    ("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("httpx", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("waybackurls", "go install github.com/tomnomnom/waybackurls@latest"),
    ("gau", "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ("unfurl", "go install github.com/tomnomnom/unfurl@latest"),
    ("whatweb", "sudo apt install -y whatweb"),
    ("massdns", "sudo apt install -y massdns")
]

vuln_tools = [
    ("nuclei", "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
    ("dalfox", "GOPROXY=direct go install github.com/hahwul/dalfox/v2@latest"),
    ("ffuf", "go install github.com/ffuf/ffuf@latest"),
    ("dirsearch", "sudo apt install -y dirsearch"),
    ("sqlmap", "sudo apt install -y sqlmap"),
    ("arjun", "pip3 install arjun --break-system-packages")
]

network_tools = [
    ("naabu", "sudo apt install -y libpcap-dev && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("asnmap", "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    ("tlsx", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"),
    ("cdncheck", "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    ("httprobe", "go install github.com/tomnomnom/httprobe@latest"),
    ("shuffledns", "GOPROXY=direct go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest")
]

utility_tools = [
    ("gf", "go install github.com/tomnomnom/gf@latest"),
    ("qsreplace", "GOPROXY=direct go install github.com/tomnomnom/qsreplace@latest"),
    ("urlhunter", "GOPROXY=direct go install github.com/utkusen/urlhunter@latest"),
    ("update-fingerprints", "go install github.com/projectdiscovery/fingerprints/cmd/update-fingerprints@latest")
]

misc_tools = [
    ("nmap", "sudo apt install -y nmap"),
    ("dirb", "sudo apt install -y dirb")
]

# ----------------- INSTALLATION FUNCTION ----------------
def is_installed(tool_name):
    if shutil.which(tool_name):
        return True
    go_path = Path.home() / "go" / "bin" / tool_name
    return go_path.exists()

def install_tool(name, cmd):
    print(f"[*] Checking {name}...")
    if is_installed(name):
        print(f"[✔] {name} already installed ✅")
        return "already", None
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        print(f"[✔] {name} installed successfully ✅")
        return "installed", None
    except subprocess.CalledProcessError as e:
        print(f"[✘] {name} failed to install ❌")
        return "failed", e.stderr.decode().strip() if e.stderr else "Unknown error"

# ------------------ MAIN SCRIPT --------------------
if __name__ == "__main__":
    all_tools = list({name: cmd for name, cmd in recon_tools + vuln_tools + network_tools + utility_tools + misc_tools}.items())

    already_installed = 0
    newly_installed = 0
    failed = 0
    failed_tools = []

    for name, cmd in all_tools:
        result, error_msg = install_tool(name, cmd)
        if result == "already":
            already_installed += 1
        elif result == "installed":
            newly_installed += 1
        else:
            failed += 1
            failed_tools.append((name, error_msg))

    total = len(all_tools)
    print("\n[✔] All tools processed.")
    print(f"Total tools: {total}")
    print(f"Already installed: {already_installed}")
    print(f"Newly installed: {newly_installed}")
    print(f"Failed to install: {failed}")

    if failed_tools:
        print("\n[✘] Tools that failed to install with errors:")
        for name, error in failed_tools:
            print(f"- {name}: {error}")
