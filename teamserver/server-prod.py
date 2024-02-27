from teamserver import create_app
import subprocess
import os
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description="""

Teamserver (production server) usage:     python3 server-prod.py server                         

""", usage='python3 %(prog)s server', formatter_class=RawTextHelpFormatter)
parser.add_argument('server', help='Run the teamserver')
args = parser.parse_args()

def pyclean(dir = "."):
    try:
        subprocess.run(["py3clean", dir], check = True)
        print("[+] py3clean was executed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while running py3clean: {e}")

def run_wsgi():

    try:
        subprocess.run(["gunicorn", "-w", "4", "teamserver:create_app()"], check = True)
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while running Gunicorn server: {e}")
    except KeyboardInterrupt:
        print("[!] Gunicorn server stopped!")

def main():

    # Remove __pycache__ directory
    pyclean()

    # Run the gunicorn server
    run_wsgi()

if __name__ == "__main__":
    main()
