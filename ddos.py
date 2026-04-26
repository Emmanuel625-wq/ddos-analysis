#DDos Log Analysis Program

from ipwhois import IPWhois

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


def classify_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return "Unknown"

    try:
        first = int(parts[0])
    except:
        return "Unknown"

    if 1 <= first <= 126:
        return "A"
    elif 128 <= first <= 191:
        return "B"
    elif 192 <= first <= 223:
        return "C"
    elif 224 <= first <= 239:
        return "D"
    elif 240 <= first <= 254:
        return "E"
    else:
        return "Unknown"




def lookup_ip_info(ip):
    try:
        obj = IPWhois(ip)
        data = obj.lookup_rdap()

        network = data.get("network", {})
        country = network.get("country", "Unknown")
        description = network.get("name", "No description")

        return country, description
    except:
        return "Unknown", "Lookup failed"
    
def write_report_file(ip_info_list, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for info in ip_info_list:
            f.write(f"IP Address: {info['ip']}\n")
            f.write(f"Class: {info['class']}\n")
            f.write(f"Country: {info['country']}\n")
            f.write(f"Description: {info['description']}\n")
            f.write("-" * 40 + "\n")

    


    









def main():
    lines = read_log_file("DDoSRawLog.txt")
    unique_ips = get_unique_ips(lines)

    ip_info_list = []
    for ip in sorted(unique_ips):
        ip_class = classify_ip(ip)
        country, desc = lookup_ip_info(ip)

        ip_info_list.append({
            "ip": ip,
            "class": ip_class,
            "country": country,
            "description": desc
        })

    write_ips_file(unique_ips, "ips.txt")
    write_report_file(ip_info_list, "report.txt")





if __name__ == "__main__":
    main()
