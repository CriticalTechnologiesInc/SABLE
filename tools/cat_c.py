import sys

def main():
    for fp in sys.argv[1:]:
        f = open(fp, 'r')
        print('#line 1 \"', fp, '\"')
        print(f.read())
        f.close()

if __name__ == '__main__':
    main()
