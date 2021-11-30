import scapy.all as scapy

def scanip(ip):  # objects formed through the classes of scapy.
    arp_request = scapy.ARP(pdst=ip)  # sending the request in form of packets to all devices with ip stored in "scanip"
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # broadcasting the packets with mac address over the ethernet
    broadcast_arp_request = broadcast/arp_request #combining both the requests to form a single object using both instances
    #print(broadcast_arp_request.summary())  #printing the summary of the combined object
    #answered, unasnwered = scapy.srp(broadcast_arp_request, timeout=1) #SR stands for send and recieve so this srp function uses our generated packets to send and recieved.
    answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose= False)[0]
    print("IP\t\t\tMAC ADDRESS\n-------------------------------------")
    # print(answered.summary())                                                        #answered and unanswered are two places where recieved responses are saved.
    # here answered ips will be printed
    clients_list =[]
    for element in answered_list:
        clients_dict ={"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return(clients_list)

def print_result(results_list):
    print("IP\t\t\tMAC ADDRESS\n-------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["MAC"])





scan_result= scanip("10.20.89.1/24")
print_result(scan_result)