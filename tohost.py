import paramiko
import traceback

hostname = 'localhost'
username = 'user'  # with sudo
password = 'password'

repository = r'https://github.com/roberttkach/server-security'
remote_directory = fr'/home/{username}/server-security'

SPLUNK_URL = 'https://example.com'
SPLUNK_TOKEN = 'splunk_token'

ssh = paramiko.SSHClient()
try:
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)

    stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_directory}")
    stdout.channel.recv_exit_status()

    _, stdout, _ = ssh.exec_command(f"git clone {repository} {remote_directory}")
    stdout.channel.recv_exit_status()

    commands = f"""
    export TERM=xterm
    export SPLUNK_URL='{SPLUNK_URL}'
    export SPLUNK_TOKEN='{SPLUNK_TOKEN}'

    if [ -d "{remote_directory}" ]; then
        cd {remote_directory};
    else
        mkdir -p {remote_directory} && cd {remote_directory};
    fi

    echo {password} | sudo -S chmod 755 .;
    echo {password} | sudo -S apt-get update
    echo {password} | sudo -S apt-get install -y libpcap-dev snapd bison gcc make

    if ! command -v snap &> /dev/null; then
        echo "Installing snap...";
        sudo apt update;
        sudo apt install snapd;
    fi

    if ! go version | grep -q "go1.22.2"; then
        wget https://golang.org/dl/go1.22.2.linux-amd64.tar.gz;
        tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz;
    fi

    echo {password} | sudo -S systemctl start snapd.service;

    cd {remote_directory};

    echo "{username} ALL=NOPASSWD:/home/{username}/server-security/checkSHH.sh" | sudo EDITOR='tee -a' visudo
    echo "{username} ALL=NOPASSWD:/home/{username}/server-security/clamav.sh" | sudo EDITOR='tee -a' visudo
    echo "{username} ALL=NOPASSWD:/home/{username}/server-security/netstat.sh" | sudo EDITOR='tee -a' visudo

    go mod init server-security;
    go mod tidy
    """

    _, stdout, _ = ssh.exec_command(commands)

    for line in stderr:
        print(line)

except paramiko.AuthenticationException:
    print("Authentication error, check your username and password")
except paramiko.SSHException as sshException:
    print("Unable to establish SSH connection: ", sshException)
except Exception as e:
    print("An error occurred: ", e)
    traceback.print_exc()
finally:
    ssh.close()
