# 🌍 **UAC COD GeoFence**

## ✨ Overview

**UAC COD GeoFence** is your ultimate Python-powered GUI companion for mastering network control. With a focus on Windows Firewall rules, this tool gives you the power to easily manage geographic-based access and specific IP ranges. Say goodbye to complexity and hello to a streamlined, intuitive experience tailored for efficiency and style.

![CodGeoFence](https://github.com/user-attachments/assets/1cdc16be-19fc-4503-bc77-7d806f1f2323)


## 🚀 Features

- **🌐 Block/Unblock Countries**: Take control of traffic with a click—block or unblock entire countries effortlessly.
- **📋 Manage IP Ranges**: Fine-tune your network access by adding or removing IP ranges and domains.
- **✅ Allow Specific IPs**: Securely configure trusted login servers for seamless access.
- **🎮 COD Texture Streaming**: Specialized management for Call of Duty texture streaming IP ranges.
- **💡 User-Friendly Interface**: Powered by PySide6, the intuitive GUI offers a hassle-free experience.
- **📜 Real-Time Logging**: Keep track of all operations with transparent, real-time logs.
- **🌙 Dark Theme**: Enjoy a modern, sleek dark theme designed for comfort and aesthetics.

## 🛠 Installation

### 📋 Prerequisites

- **Python 3.8+**
- **pip** (Python package installer)
- **Windows OS** (Windows-specific firewall management)

### 🌀 Clone the Repository

Before proceeding, make sure to **run CMD or PowerShell as Administrator** to ensure proper permissions for the following steps.

```bash
git clone https://github.com/yourusername/UAC-COD-GeoFence.git
cd UAC-COD-GeoFence
```

### ⚙️ Install Dependencies

It's recommended to set up a virtual environment for a clean installation.

```bash
python -m venv venv
# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

Alternatively, install dependencies manually:

```bash
pip install PySide6
```

### ▶️ Run the Application (Run as Admin)

```bash
# Make sure to run as administrator
python blackOps-warzone-GeoFence.py
```

## 🎯 Usage

1. **🌍 Select Country**: Choose a country from the dropdown to manage its IP ranges.
2. **📖 View IP Ranges**: Explore existing IP ranges and domains for the selected country.
3. **➕ Add IP Range/Domain**:
    - Input a new IP range in the format `start_ip-end_ip` or add a domain name.
    - Click "Add IP Range" to save your entry.
4. **❌ Remove IP Range/Domain**:
    - Select an entry from the list.
    - Click "Remove Selected IP Range" to delete it.
5. **🔒 Block/Unblock**:
    - Manage firewall rules using the "Block Country" or "Unblock Country" buttons.
6. **🛡 Block All Except**:
    - Block traffic from all countries except the selected one with ease.
7. **🎮 COD Texture Streaming**:
    - Block or unblock Call of Duty streaming-specific IP ranges.So that you can completely prevent the download of unnecessary textures in Call of Duty:Black ops 6 and avoid lag in the game
8. **🚪 Quit Application**:
    - Exit the application by clicking "Quit."

### 🔍 Finding and Adding IP Ranges with NetLimiter

When playing **Call of Duty**, especially when joining a lobby, the game connects to specific IP ranges for its servers. These IP ranges can change over time, so it’s essential to identify and update them as needed. Here’s how to find and add these ranges using **NetLimiter**:

1. **Open NetLimiter**:
   - Start the application and monitor the network activity while launching and playing Call of Duty.

2. **Identify the IP Addresses**:
   - Focus on the connections associated with Call of Duty. These IPs represent the servers the game is communicating with.

3. **Locate Geographic Information**:
   - Use IP geolocation services or tools, such as WHOIS, to determine the locations of the IP ranges. The WHOIS lookup can provide details like ownership and geographic location of the IPs. This step helps you identify the IP range effectively.

4. **Add New IP Ranges**:
   - Once identified, add these IP ranges to `ip_ranges.json` in the appropriate section.

5. **Repeat as Needed**:
   - Since IP ranges can change, periodically monitor and update the list to maintain accurate control.

### ⚠️ Important Notes:

- Always run **CMD** or **PowerShell** with administrator privileges when working with firewall rules to ensure the changes are applied correctly. Without admin access, the commands might fail or be ignored.

## ⚙️ Configuration

The application uses `ip_ranges.json` to store and manage IP ranges by country. If the file doesn’t exist on first launch, it will auto-generate default entries.

### 🛠 Editing `ip_ranges.json`

Manually customize `ip_ranges.json` to add or adjust IP ranges and domains. Ensure the JSON structure is valid to avoid issues.

```json
{
    "Germany": {
        "domains": [],
        "ip_ranges": [
            "13.32.0.0-13.32.255.255",
            "146.0.0.0-146.0.255.255"
        ]
    },
    "France": {
        "domains": [],
        "ip_ranges": [
            "92.204.0.0-92.204.255.255",
            "95.179.0.0-95.179.255.255"
        ]
    },
    "COD_texture_streaming": {
        "ip_ranges": [
            "2.16.192.0-2.16.207.255",
            "2.19.126.208-2.19.126.215"
        ]
    }
}
```

## 🤝 Contribution

We’d love your help! Here’s how to contribute:

1. **🔗 Fork the Repository**
2. **🌱 Create a Branch**:

   ```bash
   git checkout -b feature/YourFeature
   ```

3. **💾 Commit Your Changes**:

   ```bash
   git commit -m "Add some feature"
   ```

4. **⬆️ Push Your Branch**:

   ```bash
   git push origin feature/YourFeature
   ```

5. **📬 Submit a Pull Request** with an explanation of your changes.

## ⭐ Show Your Support

If you find this project helpful, please give it a star ⭐ on GitHub! Your support means a lot and helps keep the project alive.

## 📜 License

This project is licensed under the **MIT License**—free to use, modify, and share!

## 🙌 Acknowledgments

- Built with ❤️ using PySide6
- Inspired by the best in network management tools
