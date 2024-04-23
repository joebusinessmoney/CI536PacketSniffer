import platform
import time
import subprocess
import sys
import os

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

    def installScapy(self, package, action):
        try:
            command = [sys.executable, "-m", "pip", "install", action, package]

            if self.os == "Linux":
                command.insert(4, "--target")
                command.insert(5, "/usr/lib/python3/dist-packages")
            subprocess.check_call(command)

            if action == "--upgrade":
                print("*** Scapy Successfully Upgaded, System Will Now Reboot... ***")

                time.sleep(3)

                python_executable = sys.executable
                os.execl(python_executable, python_executable, *sys.argv)
            else:
                print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                return True
        except Exception as error:
            print(error)
            return False

    def checkDependencies(self):
        try:
            import scapy
            if scapy.__version__ != "2.5.0":
                print("*** Older Version of Scapy is Installed, Installing Upgraded Version... ***")

                time.sleep(3)
                
                self.installScapy("scapy", "--upgrade")
            else:
                print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                return True
        except ImportError:
            install = input("*** Scapy is Not Installed on This Device. This Dependency is Required for This Program. Would You Like to Install it? (Y/n) ***")

            if install.lower() in ["y", "yes"]:
                installed = self.installScapy("scapy", "install")
                return installed
            else:
                return False

    def startUp(self):
        print(self._banner)
        print("*** Detecting Host Operating System ... ***")
        time.sleep(3)

        print("*** Host Operating System Detected: " + self.os + " ***")

        print("*** Checking if Dependency 'Scapy' is Installed ... ***")
        time.sleep(3)

        complete = self.checkDependencies()

        if complete:
            time.sleep(3)
            
            from mvc import MVC
            mvc = MVC(self.os)
            mvc.mainloop()
        else:
            print("*** Exiting Program ***")
            quit()

main = Main()
main.startUp()
