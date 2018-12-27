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

with open(filename,'r') as csvfile:
    plots = csv.reader(csvfile, delimiter=',')
    for row in plots:
        x.append(str(row[0]))
        y.append(float(row[1]))

if limit > 0:
    x = [a for _,a in sorted(zip(y, x), reverse=True)]
    y = sorted(y, reverse=True)
    x = x[:limit]
    y = y[:limit]

plt.bar(x,y)
plt.xlabel(xname)
plt.ylabel(yname)
plt.title(title)
#plt.legend()

plt.savefig(outname)