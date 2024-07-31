# MeowPing

MeowPing is a command-line utility for testing network connectivity using ICMP echo requests or TCP connections. It provides similar functionality to traditional ping utilities but with a touch of whimsy and color. MeowPing supports both domain names and IP addresses, allowing users to check the availability and responsiveness of network hosts.

## Features

- ICMP echo request-based network testing.
- TCP connection-based network testing.
- HTTP(S) request-based network testing. (WiP)
- Colorful and visually appealing output.
- Display of connection statistics including success rate, minimum, maximum, and average connection times.
- Works with IPv4, IPv6 and Domains.

## Usage

MeowPing offers a simple command-line interface with various options:

```powershell
meowping <destination> [OPTIONS]

ARGS:
    <destination>           Specify the destination to ping (can be an IP address or domain name)

OPTIONS:
    -h, --help              Prints the Help Menu
    -p, --port <port>       Set the port number (default: ICMP, with: TCP)
    -t, --timeout <ms>      Set the timeout for each connection attempt in milliseconds (default: 1000ms)
    -c, --count <count>     Set the number of connection attempts (default: 65535)
    -m, --minimal           Changes the Prints to be more Minimal (WiP)
```

### Example Usage

```powershell
./meowping 8.8.8.8 -p 53
```

## Preview

![WindowsTerminal_ceZfc3Wia3](https://github.com/Entytaiment25/meowping/assets/64799287/b4365dc0-70de-427b-b6a2-53d919aee4eb)
