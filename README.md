---

# QuickPyScan

QuickPyScan is a Python script designed for port scanning on an IP address to detect open ports. It's intended for network analysis.

## Dependencies

1. Install the required packages:

```bash
pip install -r requirements.txt
```

## Features

- Scans specified ports or a range of ports on an IP address.
- Supports custom timeout for connection attempts.
- Allows specifying the thread limit for concurrent port scanning.

## Usage

```bash
python3 QuickPyScan.py [options] Ip-address
```

### Options

- `-h, --help`: Display the usage guide.
- `-p PORTS`: Specify ports to scan (e.g., `-p1-1024`, `-p80,443`).
- `-p-`: Scan all 65535 ports.
- `-t TIMEOUT`: Specify the timeout in seconds for each connection attempt (e.g., `-t0.5`).
- `-TH THREADS`: Specify the thread limit for scanning ports (e.g., `-TH400`).

## Examples

- Scan ports on IP address `192.168.1.1` with a thread limit of 200:
  ```bash
  python3 QuickPyScan.py -p1-1024 192.168.1.1 -TH200 -th0.5
  ```

- Scan all ports on IP address `192.168.1.1`:
  ```bash
  python3 QuickPyScan.py -p- 192.168.1.1
  ```

## Contributing

Feel free to contribute to this project. Fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
