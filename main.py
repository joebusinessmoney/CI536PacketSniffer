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

    def installPackage(self, package, action):
        try:
            command = [sys.executable, "-m", "pip", action, package]

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

    def checkCustomTkinter(self):
        try:
            import customtkinter
            print("*** Customtkinter is already installed. ***")
            return True
        except ImportError:
            install = input("*** Customtkinter is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***")
            if install.lower() in ["y", "yes"]:
                installed = self.installPackage("customtkinter", "install")
                return installed
            else:
                return False

    def checkDependencies(self):
        try:
            import scapy.all as scapy
            print("*** Scapy is Installed, Initialising Packet Sniffer ***")
            return True
        except ImportError:
            install = input("*** Scapy is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***")
            if install.lower() in ["y", "yes"]:
                installed = self.installPackage("scapy", "install")
                return installed
            else:
                return False

    def startUp(self):
        print(self._banner)
        print("*** Detecting Host Operating System: " + self.os + " ***")
        time.sleep(3)

        print("*** Checking if Dependencies are Installed ... ***")
        scapy_installed = self.checkDependencies()
        customtkinter_installed = self.checkCustomTkinter()

        if scapy_installed and customtkinter_installed:
            time.sleep(3)
            from mvc import MVC  # Ensure this import works for your actual MVC architecture
            mvc = MVC(self.os)
            mvc.mainloop()
        else:
            print("*** Exiting Program ***")
            quit()


main = Main()
main.startUp()
