import re
import os

print_re = re.compile(r'print(?!\s*\()')
print3_re = re.compile(r'print\s*\(')
l = []

for root,dirs,files in os.walk('.'):
    for f in files:
        # print f
        fp = os.path.join(root, f)
        if f.endswith('.py'):
            # print 'Processing',f
            data=open(fp).read()
            if not print3_re.search(data) and print_re.search(data):
                l.append(fp)

for i in l:
    print i
