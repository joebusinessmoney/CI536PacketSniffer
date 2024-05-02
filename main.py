import os
import subprocess
import sys
import platform
import time

class Main():
    _banner = ('''
     _____  __                __   _                  ____                __          __     _____         _  ____ ____          
    / ___/ / /_ ____ _ _____ / /_ (_)____   ____ _   / __ \ ____ _ _____ / /__ ___   / /_   / ___/ ____   (_)/ __// __/___   _____
    \__ \ / __// __ `// ___// __// // __ \ / __ `/  / /_/ // __ `// ___// //_// _ \ / __/   \__ \ / __ \ / // /_ / /_ / _ \ / ___/
    __/ // /_ / /_/ // /   / /_ / // / / // /_/ /  / ____// /_/ // /__ / ,<  /  __// /_    ___/ // / / // // __// __//  __// /    
  /____/ \__/ \__,_//_/    \__//_//_/ /_/ \__, /  /_/     \__,_/ \___//_/|_| \___/ \__/   /____//_/ /_//_//_/  /_/   \___//_/    
                                         /____/      
    ''')

    def __init__(self):
        self.env_name = "myenv"
        self.requirements_file = "requirements.txt"
        self.os_system = platform.system()
        self.ensure_virtual_environment()

    def installScapy(self, package, action):
        try:
            command = [sys.executable, "-m", "pip", "install", action, package]

            if self.os_system == "Linux":
                command.insert(4, "--target")
                command.insert(5, "/usr/lib/python3/dist-packages")

            subprocess.check_call(command)

            if action == "--upgrade":
                print("*** Scapy Successfully Upgraded ***")
                print("Please reboot your system for changes to take effect.")
            else:
                print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                return True
        except subprocess.CalledProcessError as error:
            print("Error during installation:", error)
            return False
        except Exception as error:
            print("An unexpected error occurred:", error)
            return False

    def installPackage(self, package, action):
        try:
            command = [sys.executable, "-m", "pip", "install", action, package]

            if self.os_system == "Linux":
                command.insert(4, "--target")
                command.insert(5, "/usr/lib/python3/dist-packages")

            subprocess.check_call(command)

            if action == "--upgrade":
                print(f"*** {package.capitalize()} Successfully Upgraded ***")
                print("Please reboot your system for changes to take effect.")
            else:
                print(f"*** {package.capitalize()} is Installed ***")
                return True
        except subprocess.CalledProcessError as error:
            print("Error during installation:", error)
            return False
        except Exception as error:
            print("An unexpected error occurred:", error)
            return False

    def ensure_virtual_environment(self):
        if self.os_system == "Linux":
            if 'VIRTUAL_ENV' not in os.environ:
                print("*** Creating virtual environment ***")
            if self.create_virtual_environment():
                self.activate_virtual_environment()
            else:
                print("*** Failed to create virtual environment ***")
                return False
        else:
            print("*** Virtual environment already exists ***")
            return True

    def create_virtual_environment(self):
        if self.os_system == "Linux":
            try:
                subprocess.check_call([sys.executable, "-m", "venv", self.env_name])
                return True
            except subprocess.CalledProcessError as error:
                print("Error creating virtual environment:", error)
                return False

    def activate_virtual_environment(self):
        if self.os_system == "Linux":
            os.system(f"call {self.env_name}\\Scripts\\activate.bat")
        else:
            os.system(f"source {self.env_name}/bin/activate")

    def checkDependencies(self):
        try:
            import scapy
            if scapy.__version__ != "2.5.0":
                print("*** Older Version of Scapy is Installed, Installing Upgraded Version... ***")
                time.sleep(3)
                return self.installScapy("scapy", "--upgrade")
            else:
                print("*** Scapy is Installed, Initialising Packet Sniffer ***")
                return True
        except ImportError:
            install = input("*** Scapy is Not Installed on This Device. This Dependency is Required for This Program. Would You Like to Install it? (Y/n) ***")
            if install.lower() in ["y", "yes"]:
                return self.installScapy("scapy", "install")
            else:
                return False
     
    def checkPandas(self):
        try:
            import pandas as pd
            print("*** Pandas is Already Installed ***")
            return True
        except ImportError:
            install = input("*** Pandas is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***").strip().lower()
            if install in ["y", "yes"]:
                installed = self.installPackage("pandas", "install")
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
    
    def checkSklearn(self):
        if self.os_system != "Linux":
            try:
                from sklearn.ensemble import RandomForestClassifier
                print("*** Sklearn is Already Installed ***")
                return True
            except ImportError:
                install = input("*** Sklearn is Not Installed. This Dependency is Required. Would You Like to Install it? (Y/n) ***").strip().lower()
            if install in ["y", "yes"]:
                installed = self.installPackage("scikit-learn", "install")
                return installed
            else:
                 return False
                 
    def checkScapy(self):
        try:
            import scapy

            if self.os_system == "Linux":
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
               

    def start_up(self):
        print(self._banner)
        print("*** Detecting Host Operating System: " + self.os_system + " ***")
        time.sleep(2)

        print("*** Checking if Dependencies are Installed ... ***")
        if all([self.checkScapy(), self.checkCustomTkinter(), self.checkPandas(), self.checkSklearn()]):
            time.sleep(2)
            from mvc import MVC
            mvc = MVC(self.os_system)
            mvc.mainloop()
        else:
            print("*** Exiting Program ***")

main = Main()
main.start_up()