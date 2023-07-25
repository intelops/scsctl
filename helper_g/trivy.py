import subprocess

def install_trivy():
    try:
        subprocess.run(
            "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $HOME/.local/bin",
            shell=True,
            check=True,
        )
        print("Trivy installation successful.")
    except subprocess.CalledProcessError as e:
        print(f"Trivy installation failed: {e}")