from argparse import ArgumentParser, Namespace
import os
import signal
from sys import exit
from typing import Any, Callable, Dict

from fastapi import FastAPI
from gunicorn.app.base import BaseApplication

from routers import router
from wazuh.core import common, daemon

MAIN_PROCESS = 'wazuh-comms-apid'

app = FastAPI()
app.include_router(router)


def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API host.")
    parser.add_argument("-p", "--port", type=int, default=5000, help="API port.")
    parser.add_argument("-f", "--foreground", type=bool, default=False, help="Run API in foreground mode.")

    return parser.parse_args()


class StandaloneApplication(BaseApplication):
    def __init__(self, app: Callable, options: Dict[str, Any] = None):
        self.options = options or {}
        self.app = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.app

if __name__ == "__main__":
    args = get_script_arguments()

    daemon.clean_pid_files(MAIN_PROCESS)
    pid = os.getpid()
    pidfile = os.path.join(common.WAZUH_PATH, common.OS_PIDFILE_PATH, f'{MAIN_PROCESS}-{pid}.pid')

    signal.signal(signal.SIGTERM, daemon.exit_handler(process_name=MAIN_PROCESS))
    try:
        options = {
            "proc_name": MAIN_PROCESS,
            "pidfile": pidfile,
            "daemon": not args.foreground,
            "bind": f"{args.host}:{args.port}",
            "workers": 4,
            "worker_class": "uvicorn.workers.UvicornWorker",
            "preload_app": True,
            "keyfile": "/var/ossec/api/configuration/ssl/server.key",
            "certfile": "/var/ossec/api/configuration/ssl/server.crt",
            "ca_certs": "ca.crt",
            "ssl_version": "TLS",
            "ciphers": ""
        }
        StandaloneApplication(app, options).run()
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)
    finally:
        daemon.delete_process(MAIN_PROCESS, pid)
