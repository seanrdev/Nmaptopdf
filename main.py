import nmap
import argparse
from reportlab.pdfgen import canvas as cv


def topdf(docname, strings):
    doc = cv.Canvas(docname, pagesize=(612.0, 792.0))
    y_position = 775
    doc.line(1, 772, 600, 772)
    host_drawn = False
    for line in strings:
        if not host_drawn:
            doc.drawString(270, y_position, line)
            host_drawn = True
            y_position -= 15
            continue
        doc.drawString(5, y_position, line)
        y_position -= 15
    doc.showPage()
    doc.save()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="IP address or hostname of target")
    parser.add_argument("-p", "--port", help="Ports to scan correct formats:"
                                             "22,80,443 or 22-443")
    parser.add_argument("--pdfname", help="Name of PDF file to save as")
    args = parser.parse_args()
    scan = nmap.PortScanner()
    scan.scan(args.host, args.port)
    string_list = []
    for host in scan.all_hosts():
        print('Host: {}'.format(scan[host].hostname()))
        string_list.append('Host: {}'.format(scan[host].hostname()))
        print('State: {}'.format(scan[host].state()))
        string_list.append('Host State: {}'.format(scan[host].state()))
        for protocol in scan[host].all_protocols():
            lport = scan[host][protocol].keys()
            sorted(lport)
            for port in lport:
                print('port: {}\tstate: {}\nname: {}'.format(port, scan[host][protocol][port]['state'],
                                                             scan[host][protocol][port]['name']))
                string_list.append(
                    'Port: {}   State: {}   Service Name: {}  Product: {}   Service Details: {}'.format(port,scan[host][protocol][port]['state'],
                                                                                                        scan[host][protocol][port]['name'],
                                                                                                        scan[host][protocol][port]['product'],
                                                                                                        scan[host][protocol][port]['extrainfo']))
                topdf('test', string_list)
