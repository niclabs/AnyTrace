import matplotlib.pyplot as plt
import csv
import sys

#font = {'size' : 14}
#matplotlib.rc('font', **font)
def autolabel(rects):
    """
    Attach a text label above each bar displaying its height
    """
    for rect in rects:
        height = rect.get_height()
        plt.gca().text(rect.get_x() + rect.get_width()/2., height + min(0.5, height*0.01),
                '%.2f' % float(height) if 0 < float(height) < 1 else '%d' % int(height),
                ha='center', va='bottom', fontsize=8)

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

# Add the grid
#plt.grid(zorder=0, axis='y')

# Set the figure size
#plt.rcParams["figure.figsize"] = [16,9]
bars = plt.bar(range(len(x)), list(map(float,y)) )
autolabel(bars)
plt.xticks(range(len(x)), x)

plt.xlabel(xname)
plt.ylabel(yname)
plt.title(title)
plt.xticks(rotation=45)

plt.tight_layout()

# Make the plot fit inside the image
plt.savefig(outname)
