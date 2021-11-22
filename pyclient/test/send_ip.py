import pysftp
import socket
from requests import get

with open('pol_test.txt', 'w') as f:
    f.write(f'IP Address(Internal) : {socket.gethostbyname(socket.gethostname())}\n')
    f.write(f'IP Address(External) : {get("https://api.ipify.org").text}')
    f.close()

host = 'ubinetlab.synology.me'
port = 64911

username = 'gz_uploader'
password = '2021smartfield'
hostkeys = None

cnopts = pysftp.CnOpts()

if cnopts.hostkeys.lookup(host) is None:
    print("Hostkey for " + host + " doesn't exist")
    hostkeys = cnopts.hostkeys  # 혹시 모르니 다른 호스트키 정보들 백업
    cnopts.hostkeys = None

file_name = 'pol_test.txt'
# local_path = '/Users/komyeongjin/Documents/KWU/골프존/raccoon/pyclient/test/'
remote_path = '/smartfield_upload/'

with pysftp.Connection(host, port=port, username=username, password=password, cnopts=cnopts) as sftp:
    if hostkeys is not None:
        print("New Host. Caching hostkey for " + host)
        hostkeys.add(host, sftp.remote_server_key.get_name(), sftp.remote_server_key)  # 호스트와 호스트키를 추가
        hostkeys.save(pysftp.helpers.known_hosts())  # 새로운 호스트 정보 저장

    sftp.put(file_name, remote_path + file_name)
    sftp.close()
