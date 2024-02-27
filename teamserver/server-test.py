import subprocess
import os
import argparse
from argparse import RawTextHelpFormatter

parser = argparse.ArgumentParser(description="""

Teamserver (test server) usage:     python3 server-test.py server                         

""", usage='python3 %(prog)s server', formatter_class=RawTextHelpFormatter)
parser.add_argument('server', help='Run the teamserver')
args = parser.parse_args()

def pyclean(dir = "."):
    try:
        subprocess.run(["py3clean", dir], check = True)
        print("[+] py3clean was executed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while running py3clean: {e}")

def run_flask():
    os.environ['FLASK_APP'] = 'teamserver'

    try:
        subprocess.run(["flask", "run", "--port", "8000"], check = True)
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while running Flask server: {e}")
    except KeyboardInterrupt:
        print("[!] Flask server stopped!")

def main():

    # Remove __pycache__ directory
    pyclean()

    # Run the flask server
    run_flask()

if __name__ == "__main__":
    main()
