#DDos Log Analysis Program

def read_log_file(filename):
    lines = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line.append(line.rstrip("\n"))
            return lines




def main():
    pass

if __name__ == "__main__":
    main()
