import pandas as pd
import threading
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from tkinter import ttk
import socket
import tkinter as tk
import customtkinter as ctk

class AI():
    def __init__(self, model):
        self.model = model
        self.unpacked_data = None
        self.total_packets = None
        self.suspicious = None
        self.suspicious_ips = None

    def label_style(widget):
        widget.configure(fg_color="#404040", text_color="#ffffff")
        
    def displayWindow(self):    
        self.ai_window = tk.Toplevel(background="#404040")
        self.ai_window.title("Packet Analysis")

        label_style = {'background': '#404040', 'foreground': 'white', 'anchor': 'w', 'font': ('Helvetica', 16)}
        title_style = {'background': '#404040', 'foreground': 'white', 'font': 'bold, 20', 'relief': 'raised'}

        self.ai_message = tk.Label(self.ai_window, text="Analysing Collected Packets, This May Take Some Time...", **label_style)

        self.ai_message.pack(pady=10)

    def getPackets(self):
        return pd.DataFrame([vars(packet) for packet in self.model.getPackets()])

    def startProcessing(self):
        # Start unpacking and processing data in a separate thread
        threading.Thread(target=self.processData, daemon=True).start()

    def processData(self):
        self.displayWindow()
        packet_data = self.getPackets()
        unpacked_data = pd.DataFrame()

        for index, row in packet_data.iterrows():
            unpacked_row = {}
            for column, value in row.items():
                if value is not None:
                    for attr, attr_value in vars(value).items():
                        unpacked_row[f"{column}_{attr}"] = attr_value
            unpacked_data = pd.concat([unpacked_data, pd.DataFrame([unpacked_row])], ignore_index=True)

        # Assign unpacked data
        self.unpacked_data = unpacked_data

        # Attribute handling
        self.attributeHandling(unpacked_data)

        try:
            self.runRFC(unpacked_data)
            self.ai_message['text'] = "Predictions Successfully Generated, Displaying Now..."

            self.processAnalysis()

            self.model.endAnalyse()
        except Exception as e:
            self.ai_message['text'] = f"Error Generating Predictions, If Issue Continues Please Report on Our Feedback Page: {str(e)}"
            return

    def attributeHandling(self, unpacked_data):
        if unpacked_data is None:
            self.ai_message['text'] = ("Error Generating Predictions, If Issue Continues Please Report on Our Feedback Page")
            return

        # Create DataFrame with all columns from columns_to_fill
        columns_to_fill = ['ether_src_mac', 'ether_dst_mac', 'ether_ether_type', 
                   'ip_src_ip', 'ip_dst_ip', 'ip_proto', 'ip_tos', 'ip_ttl', 
                   'ip_flags', 'ip_id', 'tcp_src_port', 'tcp_dst_port', 
                   'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_window', 
                   'raw_load', 'udp_src_port', 'udp_dst_port', 'udp_len', 
                   'udp_checksum', 'icmp_type', 'icmp_code', 'icmp_id', 
                   'icmp_seq']
    
        for column in columns_to_fill:
            if column in self.unpacked_data.columns: 
                if column in ['ether_src_mac', 'ether_dst_mac', 'ip_src_ip', 'ip_dst_ip', 'tcp_flags', 'tcp_window']:
                    self.unpacked_data[column].fillna(0, inplace=True)
                else:
                    self.unpacked_data[column].fillna(0, inplace=True)
            else:
                self.unpacked_data[column] = 0

    def runRFC(self, unpacked_data):
        # Read training dataset
        data1 = pd.read_csv("packets_dataset.csv")

        # Read unpacked data
        data2 = unpacked_data.copy()

        # Store a copy of IP addresses before encoding
        ip_addresses = data2['ip_src_ip'].copy()

        # Insert new classification column into data2
        data2.insert(0, 'classification', 0)

        # Get the column order from data1
        column_order = data1.columns

        # Reorder columns in data2 to match column_order
        data2 = data2[column_order]

        # Drop unnecessary columns from data1 and data2
        data1.drop(['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq', 'raw_load', 'ip_flags'], axis=1, inplace=True)
        data2.drop(['icmp_type', 'icmp_code', 'icmp_id', 'icmp_seq', 'raw_load', 'ip_flags'], axis=1, inplace=True)

        # Label encoder
        label_encoder = LabelEncoder()

        # Label encode dataset1
        for column in data1.columns:
            if data1[column].dtype == 'object':
                data1[column] = label_encoder.fit_transform(data1[column]) + 1

        # Label encode dataset2
        for column in data2.columns:
            if data2[column].dtype == 'object':
                data2[column] = label_encoder.fit_transform(data2[column].astype(str)) + 1

        # Fill missing values in classification column of data2 and convert to integer
        data2['classification'].fillna(0, inplace=True)
        data2['classification'] = data2['classification'].astype(int)

        # Scale the data1
        scaler = StandardScaler()
        data1_scaled = scaler.fit_transform(data1.drop(columns=['classification']))

        # Convert the scaled data1 back to a DataFrame
        data1_scaled_df = pd.DataFrame(data1_scaled, columns=data1.columns.drop('classification'))

        # Prepare data1 for training
        X_train = data1_scaled_df
        y_train = data1['classification']

        # Train the RandomForestClassifier
        random_forest_model = RandomForestClassifier(n_estimators=50, random_state=42)
        random_forest_model.fit(X_train, y_train)

        # Scale the data2
        data2_scaled = scaler.transform(data2.drop(columns=['classification']))
        data2_scaled_df = pd.DataFrame(data2_scaled, columns=data2.columns.drop('classification'))

        # Make predictions on data2
        predictions = random_forest_model.predict(data2_scaled_df)
        data2['classification'] = predictions

        # Find the total packets received in the dataset
        self.total_packets = len(data2)

        # Filter data2 where classification score is equal to 1 before making predictions
        classification_1 = data2[data2['classification'] == 1]
        # Find the sum of 1 values in the classification column
        self.suspicious = classification_1['classification'].sum()

        # Identify unique source IP addresses associated with suspicious packets
        if self.suspicious > 0:
            suspicious_ips = set(ip_addresses[classification_1.index])
        else:
            suspicious_ips = []

        # Store suspicious IP addresses
        self.suspicious_ips = list(suspicious_ips)

    def processAnalysis(self):

        # styling elements

        label_style = {'background': '#404040', 'foreground': 'white', 'anchor': 'w', 'font': ('Helvetica', 16)}
        red_style = {'background': '#404040', 'foreground': 'red', 'anchor': 'w', 'font': ('Helvetica', 16)}
        green_style = {'background': '#404040', 'foreground': 'green', 'anchor': 'w', 'font': ('Helvetica', 16)}
        title_style = {'background': '#404040', 'foreground': 'white', 'font': 'bold, 20', 'relief': 'raised'} 

        self.total_packets_label = ttk.Label(self.ai_window, text="Total Packets: " + str(self.total_packets), **green_style)
        self.total_packets_label.pack(pady=10)

        self.suspicious_label = ttk.Label(self.ai_window, text="Total Suspicious Packets Detected: " + str(self.suspicious), **red_style)
        self.suspicious_label.pack(pady=10)

        # Display suspicious IPs
        if self.suspicious_ips:
            suspicious_ips_text = "\n".join(str(ip) for ip in self.suspicious_ips)
            self.suspicious_ips_label = ttk.Label(self.ai_window, text="Suspicious IPs:\n" + suspicious_ips_text, **label_style)
            self.suspicious_ips_label.pack(pady=10)
        else:
            self.suspicious_ips_label = ttk.Label(self.ai_window, text="No suspicious IPs detected.", **title_style)
            self.suspicious_ips_label.pack(pady=10)


        canvas = tk.Canvas(self.ai_window, width=300, height=300, background="#404040")
        canvas.pack()

        # Calculate the angles for total packets and suspicious packets
        total_angle = 360 * (self.total_packets / (self.total_packets + self.suspicious))
        suspicious_angle = 360 - total_angle

        # Draw rectangles to represent the packets
        canvas.create_arc(50, 50, 250, 250, start=0, extent=total_angle, fill="green")
        canvas.create_arc(50, 50, 250, 250, start=total_angle, extent=suspicious_angle, fill="red")

        # Add label
        canvas.create_text(150, 20, text="Packet Distribution", font=("Arial", 14), fill="#ffffff")

        








