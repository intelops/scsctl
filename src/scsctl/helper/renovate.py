import subprocess

def check_if_node_and_npm_is_installed():
    # Check if node and npm are installed
    # If not, install them locally
    # This is required for renovate bot to work
    node_version = subprocess.run(["node", "--version"], capture_output=True)
    npm_version = subprocess.run(["npm", "--version"], capture_output=True)
    if node_version.returncode != 0 or npm_version.returncode != 0:
        print("Node or npm not installed, please install them to use scsctl with renovate")
        return False
    print("Node and npm already installed")
    return True

def check_if_renovate_is_installed_globally():
    # Install renovate bot
    # This is required for renovate bot to work
    renovate_version = subprocess.run(["renovate", "--version"], capture_output=True)
    if renovate_version.returncode != 0:
        print("Renovate bot not installed, please install using `npm install -g renovate`")
        return False
    else:
        print("Renovate bot already installed")
        return True
    
def run_renovate_on_a_repository(token, repo_name):
    command = f"renovate --token {token} {repo_name}"
    print(f"Runing renovate on repo {repo_name}")
    #run renovate command from python
    renovate_process = subprocess.run(["renovate", "--token", token,repo_name], capture_output=True)
    return renovate_process
