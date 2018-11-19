# The databasa is fetched from ftp://ftp.radb.net/radb/dbase
from sys import stdin

def process(data):
    asn = None
    prefix = None
    for line in data:
        if 'origin:' in line:
            tmp = line.lower().split("origin:",1)[1].strip()
            if 'as' in tmp:
                asn = int(tmp.split("as",1)[1])
            else:
                try:
                    asn = int(tmp)
                except ValueError:
                    pass
        elif 'route:' in line:
            prefix = line.lower().split("route:",1)[1].strip()
    if asn != None and prefix != None:
        print("{},{}".format(prefix,asn))

buffer = []
for line in stdin:
    line = line.strip()
    if line == "":
        process(buffer)
        buffer = []
    else:
        buffer.append(line)

process(buffer)
