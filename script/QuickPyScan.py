import socket
import threading
import sys
import os
import re
import time
from rich.progress import Progress
from rich import print
from rich.console import Console
from rich.table import Table


console = Console()

class CustomError(Exception):
    pass

# Some common ports
commonPorts = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 6379, 7474, 8080, 1723, 8443, 8888, 9090, 9100, 9999, 27017)
protocols = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP', 
    53: 'DNS',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: "MySQL",
    3389: "Microsoft RDP",
    5900: "VNC",
    6379: 'Redis Database',
    7474: 'Neo4j (Graph Database)',
    8080: "HTTP (Apache Tomcat)",
    1723: "PPTP",
    8443: "HTTPS (Apache Tomcat)",
    8888: "TCP/IP",
    9090: "TCP/IP",
    9100: "Raw TCP/IP Printing Service",
    9999: "TCP/IP",
    27017: 'MongoDB'
}

openports = [] # List that will contain the open ports found.
count = 0 # Count for the checkIP() function.
except_count = 0 # Count for the exception limit to display in the scanPorts() function.
portCount = 0
missed_ports = 0

def help():
    help = '[blue]Usage: [yellow]QuickPyScan.py [cyan]-p1-1024, -p- or -p80,443 Ip-adress -t0.5(Timeout-optional) -TH400(Threads-optional)'
    return help


def info():
     info_text = """
    [cyan]QuickPyScan

    [magenta]This Python script allows you to scan ports on an IP address and detect open ports.

    [blue]Usage:
      [yellow]python3 QuickPyScan.py [cyan](options) Ip-address   [magenta](The order of arguments doesn't matter.) 

    [blue]Options:
      [cyan]-h, --help            [yellow]Display usage guide.
      [cyan]-p  PORTS             [yellow]Specify ports to scan (e.g., [cyan]-p1-1024, -p80,443[yellow])
      [cyan]-p- ALL PORTS         [yellow]Scan [cyan]65535 [yellow]ports.
      [cyan]-t  TIMEOUT           [yellow]Specify the timeout in seconds for each connection attempt [cyan]-t0.5. [magenta](Default is 1 second.)
      [cyan]-TH THREADS           [yellow]Specify the thread limit for scanning ports [cyan]-TH800. [magenta](Default is 400 threads.)

    [blue]Examples:
      [magenta]Scan ports on IP address [cyan]192.168.1.1 [magenta]with a thread limit of 200:
        [yellow]python3 QuickPyScan.py [cyan]-p1-1024 192.168.1.1 -TH200 -th0.5

      [magenta]Scan all ports on IP address [cyan]192.168.1.1:
        [yellow]python3 QuickPyScan.py [cyan]-p- 192.168.1.1
    """
     
     return info_text


def checkIP(host):
    global count
    try:
        socket.inet_pton(socket.AF_INET, host)
        count += 1
        if count > 1:
            raise CustomError('Only one [cyan]IP address[yellow] is allowed.')
        return True
    except OSError:
        return False
        

def portFilter(arg):
    # Check if the input is separated by a comma
    if ',' in arg:
        # Remove the 'p' before trying to split and convert to integers
        arg = arg.replace('-p', '')
        return [int(num) for num in arg.split(',')]
    
    # We use regular expressions to find numbers in the "pX" or "pX-Y" formats and this
    match = re.match(r'-p(\d+)(?:-(\d+))?', arg)
    
    if match:
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else None
        
        if end:
            return range(start, end + 1)
        else:
            return [start]
    else:
        return None

def timeFilter(args):
    args = args.replace('-t', '')
    if args:
        if float(args) < 0.1:
            raise CustomError('[cyan]Timeout. [yellow]Invalid timeout value.')
        return float(args)

    return None  # Returns None if no time was provided.


def scanPorts(host, port, timeout):
    global except_count
    global portCount
    global missed_ports
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if timeout: # Check if timeout has a value.
                    s.settimeout(timeout)
                else:    
                    s.settimeout(1) # Default timeout.
                s.connect((host, port))
                portCount += 1 
                if port in commonPorts:
                    print(f'[blue]Open port: [cyan]| [red]{port}[yellow] {protocols[port]}')
                else:
                    print(f'[blue]Open port: [cyan]| [white]{port}')
                openports.append(port)
    except ConnectionRefusedError:
        portCount += 1
        pass
    except TimeoutError:
        portCount += 1
        pass
    except OSError:
        if except_count < 1:
            except_count += 1
            print('[red]Error: [yellow]Too many open files. [yellow]Try reducing the number of threads.')
            print("[magenta]It's likely that some ports were not scanned.")
            missed_ports += 1
        else:
            missed_ports += 1
            pass

def openPortsCheck(timeout):
        # Rich table
    table = Table(title='[cyan]Open ports')
    table.add_column('[blue]Port', style='bold')
    table.add_column('[blue]Protocol', style='bold')

    portsOpen = ', '.join(str(port) for port in openports) # We convert the list of ports to a string.
    for port in openports:
        table.add_row(f'[red]{str(port)}',f'[yellow]{protocols[port]}' ) # Add each port and its corresponding protocol to the table
    os.system('clear')
    console.print(table, '[yellow]Ports saved in the [cyan]"openPorts" [yellow]file.') # Print the table and a message
    with open('openPorts', 'w') as f:
        f.write(portsOpen) # We save the open ports to a file.
        print(f'[cyan]{portCount} ports [magenta]were successfully scanned.') # Print the ports that were successfully scanned.
        if timeout:
            if timeout < 1:
                print('\n[yellow]For more accurate results, try increasing the timeout.')

        if missed_ports > 0:
            print(f"\n[magenta]It's likely that [cyan]{missed_ports} ports[magenta] were not scanned correctly. Try reducing the number of threads for more accurate scanning.") # Print possible unscanned ports.
    

def run():
    try:
        with Progress() as progress:
            handled_args = ['-h', '--help', '-p-', '-p', '-t', '-TH'] # List of allowed arguments.
            HOST = None
            PORTS = None
            timeout = None
            THREAD_LIMIT = 400 # Default limit of concurrent threads.
            someports = None

             # Count the number of times certain arguments are repeated.
            t_count = 0
            th_count = 0
            p_count = 0

             # Iterate over all received arguments to check for errors, etc.
            for arg in sys.argv[1:]:
                if checkIP(arg):
                    HOST = arg
                    continue
                elif '-p' in arg:
                    PORTS = portFilter(arg)
                    if PORTS and '-p-' in sys.argv[1:]:
                        raise CustomError('[cyan]-p- -p [yellow]Arguments cannot be repeated.')
                    p_count += 1
                    continue
                elif '-t' in arg:
                    timeout = timeFilter(arg)
                    t_count += 1
                    continue
                elif '-TH' in arg:
                    arg = arg.replace('-TH', '')
                    if arg == '' or int(arg) < 2:
                        raise CustomError('[cyan]-TH [yellow] Please choose a valid thread count. [magenta] Minimum allowed value: [green]2.')
                    else:
                        THREAD_LIMIT = int(arg)
                        th_count += 1
                        continue

                if arg in handled_args:
                    continue
                else:
                    raise ValueError
                
            # Check that arguments are not repeated.
            if t_count > 1 or th_count > 1 or p_count >1:
                raise CustomError('[red]arg [yellow]Arguments cannot be repeated.')

            # Verify if the user wishes to see the usage guide or if he uses the argument -p-.
            if '-h' in sys.argv or '--help' in sys.argv:
                print(info())
                sys.exit(1)
            elif '-p-' in sys.argv and PORTS == None:
                PORTS = range(1, 65536)
            
            # Verify that there are no ports greater than 65535 and assign value to someports.
            if type(PORTS) == range:
                try:
                    if len(PORTS) > 65535:
                        raise CustomError('[magenta]There are only [cyan]65535 [magenta]ports..')
                    elif min(PORTS) <= min(commonPorts) and max(PORTS) >= max(commonPorts):
                        someports = commonPorts
                    elif min(PORTS) <= min(commonPorts) and max(PORTS) >= max(commonPorts[:10]):
                        someports = commonPorts[:10]
                except ValueError:
                    raise CustomError(f'Port range [cyan]{PORTS.start}-{PORTS.stop - 1} [yellow]is invalid. [magenta]Please start from lower to higher.')
            elif type(PORTS) == int:
                if PORTS > 65535:
                    raise CustomError('[magenta]There are only [cyan]65535 [magenta]ports.')
            elif type(PORTS) == list:
                no_duplicates = set(PORTS) # Eliminate duplicates from the list.
                PORTS = list(no_duplicates) # Convert the set back to a list.
                maxnum = max(PORTS)
                if maxnum > 65535:
                    raise CustomError('[magenta]There are only [cyan]65535 [magenta]ports.')

            # Verify that an IP or port exists.
            if HOST == None or PORTS == None:
                raise CustomError('[magenta]Please enter a valid [yellow]IP-address [magenta]or [yellow]Port.')

            thread_list = [] # List where concurrent threads will be saved.                             
            task = progress.add_task('[cyan]Scaning...', total=len(PORTS)) # Add a task to our progress bar.


            if someports: # If true, scan some common ports first for quick results.   
                for port in someports:
                    while threading.active_count() > THREAD_LIMIT:
                        time.sleep(0.1) # Wait if the thread limit is reached.
                    thread = threading.Thread(target=scanPorts, args=(HOST, port, timeout))
                    thread_list.append(thread)
                    thread.start()
                    progress.update(task,advance=1) # Update the progress bar.

                for t in thread_list:
                    t.join() # Wait for all threads to finish.
                    progress.update(task,advance=1) # Update the progress bar.
            
            for port in PORTS:
                if someports:
                    if port in someports: # If true, common ports have already been scanned, so we skip them.
                        continue
                while threading.active_count() > THREAD_LIMIT:
                    time.sleep(0.1) # Wait if the thread limit is reached.
                thread = threading.Thread(target=scanPorts, args=(HOST, port, timeout))
                thread_list.append(thread)
                thread.start()
                progress.update(task,advance=1) # Update the progress bar.

            for t in thread_list:
                t.join() # Wait for all threads to finish.
                progress.update(task,advance=1) # Update the progress bar.

        if openports: # If there are open ports, perform openPortsCheck
            openPortsCheck(timeout)
        else:
            os.system('clear')
            print('[yellow]Open ports not found. [magenta]For more accurate results, try increasing the timeout. [cyan]-h [yellow]or[cyan] --help [yellow]for usage guide.')
    except ValueError:
        print('[red]Unknown argument or value.[yellow] [cyan]-h [yellow]or[cyan] --help [yellow]for usage guide.')
        sys.exit(1)
    except CustomError as e:
        print(f'[red]Error: [yellow]{e} [cyan]-h [yellow]or[cyan] --help [yellow]for usage guide.')
        sys.exit(1)
    except KeyboardInterrupt:
        if openports:
            openPortsCheck(timeout)
            sys.exit(1)


if __name__ == '__main__':
    os.system('clear')
    run()