import matplotlib.pyplot as plt
from matplotlib.finance import candlestick_ohlc, candlestick2_ohlc

import csv
import sys

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
        yy.append([float(x) for x in row[1:]])

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
    plt.text(i+0.1, yy[i][0]*1.01, str(int(yy[i][0])), fontsize=8)
plt.plot(range(len(x)), [yy[i][1] for i in range(len(x))], 'go', markersize=3)
for i in range(len(x)):
    plt.text(i+0.1, yy[i][1]-1, str(int(yy[i][1])), fontsize=8)

plt.xticks(range(len(x)), x)
plt.ylabel(yname)
plt.xlabel(xname)

# draw the affected
plt.subplot(212, sharex=ax)
plt.bar(range(len(x)), [yy[i][2] for i in range(len(yy))])
plt.ylabel(y2name)
plt.xlabel(xname)
#ax.set_ylim([0, 10])

# Make the plot fit inside the image
plt.tight_layout()

plt.savefig(outname)

# Cargar un archivo con la cantidad de clientes??
# Mapear AS -> QPS (% total o local?)