import getopt, sys, os

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'n')
    except getopt.GetoptError as err:
        print(err)
        sys.exit(2)
    printLines = False
    for o, a in opts:
        if o == '-n':
            printLines = True
        else:
            print("Bad arg: " + o)
    for fp in sys.argv[1:]:
        fname, fext = os.path.splitext(fp)
        if not (fext == '.h' or fext == '.c'):
            continue
        f = open(fp, 'r')
        if printLines:
            print('#line 1 \"', fp, '\"')
        print(f.read())
        f.close()

if __name__ == '__main__':
    main()
