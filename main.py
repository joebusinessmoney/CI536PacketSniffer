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
    __/ // /_ / /_/ // /   / /_ / // / / // /_/ /  / ____// /_/ // /__ / ,<  /  __// /_    ___/ // / / // // __// __//  __// /    
  /____/ \__/ \__,_//_/    \__//_//_/ /_/ \__, /  /_/     \__,_/ \___//_/|_| \___/ \__/   /____//_/ /_//_//_/  /_/   \___//_/     
                                         /____/       
    ''')

    os = platform.system()

    def __init__(self):
        pass

    def installPackage(self, package, action):
        try:
            command = [sys.executable, "-m", "pip", "install", action, package]

            if self.os == "Linux":
                command.insert(4, "--target")
                command.insert(5, "/usr/lib/python3/dist-packages")
            subprocess.check_call(command)

            if action == "--upgrade":
                print(f"*** {package} Successfully Upgraded, System Will Now Reboot... ***")
                time.sleep(3)
                python_executable = sys.executable
                os.execl(python_executable, python_executable, *sys.argv)
            else:
                print(f"*** {package} is Installed, Initialising Application ***")
                return True
        except Exception as error:
            print(f"Failed to install {package}: {error}")
            return False

    def checkScapy(self):
        try:
            import scapy

            if self.os == "Linux":
                if scapy.__version__ != "2.5.0":
                    print("*** Older Version of Scapy is Installed, Installing Updated Version ***")
                    installed = self.installPackage("scapy", "--upgrade")
                    return installed
                else:
                    print("*** Scapy is Already Installed ***")
                    return True
                    
            print("*** Scapy is Already Installed ***")
            return True
        except ImportError:
            install = input("*** Scapy is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***")
            if install.lower() in ["y", "yes"]:
                installed = self.installPackage("scapy", "install")
                return installed
            else:
                return False
            
    def checkCustomTkinter(self):
        try:
            import customtkinter as ctk
            print("*** Customtkinter is Already Installed ***")
            return True
        except ImportError:
            install = input("*** CustomTkinter is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***").strip().lower()
            if install in ["y", "yes"]:
                installed = self.installPackage("customtkinter", "install")
                return installed
            else:
                 return False

    def startUp(self):
        print(self._banner)
        print("*** Detecting Host Operating System: " + self.os + " ***")
        time.sleep(2)

        print("*** Checking if Dependencies are Installed ... ***")
        scapy = self.checkScapy()
        customtkinter = self.checkCustomTkinter()

        if scapy and customtkinter:
            time.sleep(2)
            from mvc import MVC
            mvc = MVC(self.os)
            mvc.mainloop()
        else:
            print("*** Exiting Program ***")
            quit()


main = Main()
main.startUp()
