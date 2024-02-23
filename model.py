import re

class Model():
    def __init__(self, email):
        self.email = email

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        """
        Validate the email
        :param value:
        :return:
        """
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.fullmatch(pattern, value):
            self.__email = value
        else:
            raise ValueError(f'Invalid email address: {value}')

    def save(self):
        """
        Save the email into a file
        :return:
        """
        with open('emails.txt', 'a') as f:
            f.write(self.email + '\n')


#ignore for now:

class bdfb():
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