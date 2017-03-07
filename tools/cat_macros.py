import sys

def main():
    for fp in sys.argv[1:]:
        f = open(fp, 'r')
        print_next = False
        for l in f.readlines():
            if (l[0] == '#' and not l.startswith('#include')) or print_next:
                print(l[:-1])
            if len(l) > 1 and l[-2] == '\\':
                print_next = True
            else:
                print_next = False
        f.close()

if __name__ == '__main__':
    main()
