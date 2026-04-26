#DDos Log Analysis Program

def read_log_file(filename):
    lines = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line.append(line.rstrip("\n"))
            return lines
        


def extract_ip_from_line(line):
    marker = "[client "
    start = line.find(marker)
    if start == -1:
        return None

    ip_start = start + len(marker)
    ip_end = line.find("]", ip_start)
    if ip_end == -1:
        return None

    return line[ip_start:ip_end].strip()

def get_unique_ips(lines):
    ip_set = set()
    for line in lines:
        ip = extract_ip_from_line(line)
        if ip:
            ip_set.add(ip)
    return ip_set


def write_ips_file(ip_set, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for ip in sorted(ip_set):
            f.write(ip + "\n")








def main():
    lines = read_log_file("DDoSRawLog.txt")
    unique_ips = get_unique_ips(lines)
    write_ips_file(unique_ips, "unique_ips.txt")





if __name__ == "__main__":
    main()
