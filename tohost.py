import paramiko
import traceback

hostname = 'localhost'
username = 'username'  # with sudo
password = 'password'
deployto = 'arch-based'

splunk_url = 'https://example.com'
splunk_token = 'splunk_token'

directory = fr'/home/{username}/server-security'

commands = [
    f"git clone https://github.com/roberttkach/server-security {directory}",
    f"bash {directory}/bash/deploy/{deployto}.sh '{splunk_url}' '{splunk_token}' '{username}' '{password}'"
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=hostname, username=username, password=password)

for command in commands:
    try:
        _, stdout, _ = ssh.exec_command(command)
        stdout.channel.recv_exit_status()
    except paramiko.AuthenticationException:
        print(f"Authentication error when executing the '{command}' command, verify your username and password")
        break
    except paramiko.SSHException as sshException:
        print(f"Unable to establish SSH connection when executing '{command}': ", sshException)
        break
    except Exception as e:
        print(f"An error occurred while executing '{command}': ", e)
        traceback.print_exc()
        break

ssh.close()
