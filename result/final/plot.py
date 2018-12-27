import matplotlib.pyplot as plt
import csv
import sys

x, y = [], []
filename = sys.argv[1]
outname = sys.argv[2]
limit = int(sys.argv[3])
title = sys.argv[4]
xname = sys.argv[5]
yname = sys.argv[6]
dosort = (sys.argv[7] if len(sys.argv) > 7 else 1) == 1

with open(filename,'r') as csvfile:
    plots = csv.reader(csvfile, delimiter=',', escapechar="\\")
    for row in plots:
        x.append(str(row[0]))
        y.append(float(row[1]))

if limit > 0:
    if dosort:
        x = [a for _,a in sorted(zip(y, x), reverse=True)]
        y = sorted(y, reverse=True)
    x = x[:limit]
    y = y[:limit]

plt.rcParams["figure.figsize"] = [16,9]
plt.bar(range(len(x)), list(map(float,y)) )
plt.xticks(range(len(x)), x)

plt.xlabel(xname)
plt.ylabel(yname)
plt.title(title)
plt.xticks(rotation=45)

plt.savefig(outname)