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

    os = platform.system()

    def checkDependencies(self, package):
        try:
            import scapy
            print("*** Scapy is Installed, Initialising Packet Sniffer ***")
            return True
        except ImportError:
            install = input("*** Scapy is Not Installed on This Device. This Dependency is Required for This Program. Would You Like to Install it? (Y/n) ***")

            if install.lower() in ["y", "yes"]:
                if self.os == "Linux":
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", "--target", "/usr/lib/python3/dist-packages", package])
                        print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                        return True
                    except Exception as error:
                        print(error)
                        return False  
                else:
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                        print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                        return True
                    except Exception as error:
                        print(error)
                        return False
            else:
                return False

    def startUp(self):
        print(self._banner)
        print("*** Detecting Host Operating System ... ***")
        time.sleep(3)

        print("*** Host Operating System Detected: " + self.os + " ***")

        print("*** Checking if Dependency 'Scapy' is Installed ... ***")
        time.sleep(3)

        installed = self.checkDependencies("scapy")

        if installed:
            time.sleep(3)
            
            from mvc import MVC
            mvc = MVC(self.os)
            mvc.mainloop()
        else:
            print("*** Exiting Program ***")
            quit()

main = Main()
main.startUp()
