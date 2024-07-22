import logging
import os
import psutil
import re
import signal

from wazuh.core import common, pyDaemonModule


def assign_wazuh_ownership(filepath: str):
    """Create a file if it doesn't exist and assign ownership.

    Parameters
    ----------
    filepath : str
        File to assign ownership.
    """
    if not os.path.isfile(filepath):
        f = open(filepath, "w")
        f.close()
    if os.stat(filepath).st_gid != common.wazuh_gid() or \
        os.stat(filepath).st_uid != common.wazuh_uid():
        os.chown(filepath, common.wazuh_uid(), common.wazuh_gid())

def clean_pid_files(daemon: str) -> None:
    """Check the existence of '.pid' files for a specified daemon.

    Parameters
    ----------
    daemon : str
        Daemon's name.
    """
    regex = rf'{daemon}[\w_]*-(\d+).pid'
    for pid_file in os.listdir(common.OSSEC_PIDFILE_PATH):
        if match := re.match(regex, pid_file):
            try:
                pid = int(match.group(1))
                process = psutil.Process(pid)
                command = process.cmdline()[-1]

                if daemon.replace('-', '_') in command:
                    os.kill(pid, signal.SIGKILL)
                    print(f"{daemon}: Orphan child process {pid} was terminated.")
                else:
                    print(f"{daemon}: Process {pid} does not belong to {daemon}, removing from {common.WAZUH_PATH}/var/run...")

            except (OSError, psutil.NoSuchProcess):
                print(f'{daemon}: Non existent process {pid}, removing from {common.WAZUH_PATH}/var/run...')
            finally:
                os.remove(os.path.join(common.OSSEC_PIDFILE_PATH, pid_file))

def exit_handler(signum, frame, process_name: str, logger: logging.Logger) -> None:
    """Try to kill API child processes and remove their PID files."""
    api_pid = os.getpid()
    delete_process(process_name, api_pid, logger)

def delete_process(process_name: str, pid: int, logger: logging.Logger) -> None:
    """Delete parent and child processes."""
    pyDaemonModule.delete_child_pids(process_name, pid, logger)
    pyDaemonModule.delete_pid(process_name, pid)

def spawn_process(process_name: str) -> None:
    """Spawn general process pool child."""
    pid = os.getpid()
    pyDaemonModule.create_pid(process_name, pid)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
