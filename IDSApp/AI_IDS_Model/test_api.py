import requests

url = "http://127.0.0.1:5000/predict"

data = {
    "DstPort": 80,
    "Protocol": 6,
    "PacketSize": 512,
    "PacketCount": 10,
    "PayloadSize": 300,
    "FlowDirection": 1,
    "TcpFlags": 2
}

response = requests.post(url, json=data)
print(response.json())
