import scapy.all as scapy

class Model():
    def startUp():
        
        print(scapy.ifaces)

        print("")
        print("*** List of Currently Detected Interfaces - Please Enter the Name of the Interface You Would Like to Sniffing ***")
        print("*** NOTE - If No Selection made, Sniffing will Happen on all Interfaces ***")
        userInput = input("")


        sniff(userInput) # network interface to be sniffed (should add ability for user to select an interface of their choice)

    def sniff(interface):
        scapy.sniff(store=False, prn=processPacket) # packet sniffer function, takes network interface as
                                                                 # an input, captured packets wont be stalled, processPacket
                                                                 # will be called each time a new packet is captured

    def processPacket(packet): # this gets the packets, source and destination ip and port as well as the protocol and displays accordingly
        packet.show()

model = Model()
model.startUp()