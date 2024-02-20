import platform
import time
import subprocess
import sys

class Main():
    _banner = ('''
   _____  __                __   _                  ____                __          __     _____         _  ____ ____           
  / ___/ / /_ ____ _ _____ / /_ (_)____   ____ _   / __ \ ____ _ _____ / /__ ___   / /_   / ___/ ____   (_)/ __// __/___   _____
  \__ \ / __// __ `// ___// __// // __ \ / __ `/  / /_/ // __ `// ___// //_// _ \ / __/   \__ \ / __ \ / // /_ / /_ / _ \ / ___/
 ___/ // /_ / /_/ // /   / /_ / // / / // /_/ /  / ____// /_/ // /__ / ,<  /  __// /_    ___/ // / / // // __// __//  __// /    
/____/ \__/ \__,_//_/    \__//_//_/ /_/ \__, /  /_/     \__,_/ \___//_/|_| \___/ \__/   /____//_/ /_//_//_/  /_/   \___//_/     
                                       /____/                                                                                   
   ''')

    _os = (platform.system())

    def checkDependencies(self, package):
        try:
            import scapy.all
            print("*** Scapy is Installed, Initialising Packet Sniffer ***")
            return True
        except:
            install = input("*** Scapy is Not Installed on This Device, This Dependency is Required for This Program. Would You Like to Install it? (Y/n) ***")

            if (install == "Y" or "y"):
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                return True
            else:
                print("*** Exiting Program y***")
                quit()
            
    def startUp(self):
        print(self._banner)
        print("*** Detecting Host Operating System ... ***")
        time.sleep(3)

        print("*** Host Operating Sysem Detected: " + self._os + " ***")

        print("*** Checking if Dependancy 'Scapy' is Installed ... ***")
        time.sleep(3)

        installed = self.checkDependencies("scapy.all")
    


main = Main()
main.startUp()