import matplotlib.pyplot as plt
from matplotlib.finance import candlestick_ohlc, candlestick2_ohlc

import csv
import sys
import math

# 3 == ASN AFFECTED, 4 == QPS
USE_DATA_FROM = 3
USE_LOG = False


def autolabel(rects):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        plt.gca().text(rect.get_x() + rect.get_width()/2., height + min(0.5, height*0.01),
                '%.2f' % float(height) if 0 < float(height) < 1 else '%d' % int(height),
                ha='center', va='bottom', fontsize=8)

x, yy = [], []
filename = sys.argv[1]
outname = sys.argv[2]
limit = int(sys.argv[3])
title = sys.argv[4]
xname = sys.argv[5]
yname = sys.argv[6]
y2name = sys.argv[7]
legend = sys.argv[8].split(",")
colors = ('b', 'c', 'g')
#dosort = (sys.argv[7] if len(sys.argv) > 7 else 1) == 1

with open(filename,'r') as csvfile:
    plots = csv.reader(csvfile, delimiter=',', escapechar="\\")
    for row in plots:
        x.append(str(row[0]))
        #yy.append([float(x) for x in row[1:4]])
        yy.append([float(row[i]) for i in [1,2,USE_DATA_FROM]])

if limit > 0:
    x = x[:limit]
    yy = yy[:limit]


#fig, ax = plt.subplot(311)
ax = plt.subplot(211)
plt.title(title)

data = []
for i in range(len(x)):
    data.append((i, min(yy[i][0], yy[i][1]), yy[i][0], yy[i][1], min(yy[i][0], yy[i][1])))

# Draw the differences
candlestick_ohlc(ax, data, width=0.1)
plt.plot(range(len(x)), [yy[i][0] for i in range(len(x))], 'ro', markersize=3)
for i in range(len(x)):
    plt.text(i-0.6, yy[i][0]*1.01, str("%.1f" % (yy[i][0])), fontsize=8)
plt.plot(range(len(x)), [yy[i][1] for i in range(len(x))], 'go', markersize=3)
for i in range(len(x)):
    #plt.text(i+0.1, yy[i][1]*0.9, str(int(yy[i][1])), fontsize=8)
    plt.text(i+0.1, yy[i][1]*0.98, str("%.1f" % (yy[i][1])), fontsize=8)

plt.xticks(range(len(x)), x)
plt.ylabel(yname)
plt.xlabel(xname)
plt.legend(legend[0:2])

# draw the affected
plt.subplot(212, sharex=ax)
if USE_LOG:
    plt.gca().set_yscale("log", nonposy='clip')
plt.bar(range(len(x)), [yy[i][2] for i in range(len(yy))])
plt.ylabel(y2name)
plt.xlabel(xname)
plt.yticks()

#ax.set_ylim([0, 10])
#plt.legend(legend[2:])


# Make the plot fit inside the image
plt.tight_layout()

plt.savefig(outname)

# Cargar un archivo con la cantidad de clientes??
# Mapear AS -> QPS (% total o local?)