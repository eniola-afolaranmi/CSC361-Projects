import ssl
import socket
import sys
import re


def port_checker(url):
    port = 443  # If there is no mention in the url, set the port to 80
    context = ssl.create_default_context() #and attempt to connect to a server
    conn = context.wrap_socket(socket.socket(
            socket.AF_INET), server_hostname=url)
    try:
        conn.connect((url, port))
        conn.close()
    except ssl.SSLError: #if this causes an error, that means we are trying to open over the wrong port
        port = 80 #so, make port 443
    except socket.gaierror: #If website doesn't exist
        print("ERROR")
        print("This website isn't found :(")
        print("Closing Program...")
        sys.exit() #close client
    except:
        print("ERROR IN CONNECTION")
        print(f"Possible Causes: \r\n   Spelling Mistakes in {url}'s domain extension\r\n   {url} took too long to respond\r\n   And More")
        print("Closing Program...")
        sys.exit()

    return port

def parse_input(uri):
    filepath = ''
    port = 0
    if "//" in uri: #If there is a // in the uri, this means that the protocol is mentioned
        if "http" in uri: #if the given url includes http
            if "https" in uri: # check if it is https
                port = 443 
            else:
                port = 80 #if it's not, it is http
        uri = uri.split("//")[1] # remove the protocol after using it to check for port
        if "/" in uri:
            url, filepath= uri.split('/', 1)[0], uri.split("/", 1)[1] #If there is another slash, everything after that slash is the filepath

    if "/" in uri:
        url, filepath= uri.split('/', 1)[0], uri.split("/", 1)[1] 
    else:
        url = uri # if there are no / in the uri,

    if ":" in url:
        url = url.split(":")[0] # If there is a port in the url, remove it

    if port ==0: #if the port hasn't already been checked, 
        port = port_checker(url)  # check 

    return url, filepath, port


def cookie_check(filepath, url, port):
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1'])
    conn = context.wrap_socket(socket.socket(
        socket.AF_INET), server_hostname=url)
    conn.connect((url, port))
    http_request = f"GET /{filepath} HTTP/1.1\r\nHost: {url}\r\n\r\n"
    print(http_request)
    print("--- Request Sent ---\r\n")
    conn.send(http_request.encode())
    result = conn.recv(10000).decode()
    conn.close()
    print(" --- Response Received--- \r\n")
    print(result.split("\r\n\r\n")[0] + "\r\n\r\n --- BODY HIDDEN --- \r\n")
    print(" --- End of Response ---")
    print(" --- Response Code: ",result.split("\n")[0]) #prints the first line of the result
    response = result.split()[1] # response equal to code (i.e. 200)
    cookie_list = re.findall("^Set-Cookie:.*", result,re.M | re.I) #Takes any lines that start with Set-Cookie and puts them in a cookie list

    while response in ["301", "302"]: #if there is a redirection necessary
        print(" --- Redirection Needed --- ")
        location = re.search("Location:.+\n", result, re.IGNORECASE) #Take the given location
        location = location.group().strip()
        location = location.split(' ')[1]

        if location == None: #If the location is None, no valid location to go to was given
            print('No valid location given:', location)
            break
        elif location == '/':
            filepath='' # this means there is no filepath and the url stays the same
        else:
            url, filepath, port = parse_input(location) #find the new filepath and url through parse_input

        cookie_str = "".join(cookie_list) #prepare the cookie list to pass through the header
        cookie_str = cookie_str.replace('\r', '\r\n')
        cookie_str=(cookie_str).replace('set-','').replace('Set-','')

        print(f"\n --- Redirecting to {url} ---")
        http_request = f"GET /{filepath} HTTP/1.1\r\nHost: {url}\r\n{cookie_str}\r\n\r\n"
        print(http_request)
        print(" --- Request Sent --- \r\n")
        conn = context.wrap_socket(socket.socket(
        socket.AF_INET), server_hostname=url)
        conn.connect((url, port))
        conn.send(http_request.encode())
        result = conn.recv(10000).decode()
        print(" --- Response Received --- ")
        print(result.split("\r\n\r\n")[0] + "\r\n\r\n --- BODY HIDDEN --- \r\n")
        print(" --- End of Response --- ")
        print(" --- Response Code: ", result.split("\n")[0])
        response = result.split()[1]

        new_cookies=re.findall("^Set-Cookie:.*", result,re.M | re.I) #Save any new cookies found
        for cookie in new_cookies:
            if cookie not in cookie_list:
                cookie_list.append(cookie)
    
        conn.close()

    if response in ["401", "403"]: #If either password protected code is given by the response
        print(" --- Password Needed to Proceed ---")
        password = "This website IS password protected!\r\n"
    else:
        print(" --- Password Not Needed ---")
        password = "This website is NOT password protected\r\n"

    if response in ["404"]: #If a website is not found, close client
        print("No website was found :(")
        print("Closing Program....")
        sys.exit()

    h2 = check_h2(url, port) #Check if website is http2 supporting

    if response == "200":
        print(" --- Information Found!! ---")    

    return cookie_list, password, h2


def check_h2(url, port):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(
        socket.AF_INET), server_hostname=url)
    context.set_alpn_protocols(['http/1.1', 'h2'])
    conn.connect((url, port))
    if conn.selected_alpn_protocol() != None:
        if "h2" in conn.selected_alpn_protocol():
            print(" --- HTTP2 Supported! --- ")
            h2 = "http2 IS supported!!"
        else:
            print(" --- HTTP2 NOT Supported --- ")
            h2 = "http2 is NOT supported"
    else:
        h2 = "http2 is NOT supported"
    conn.close()

    return h2

def main():
    print("--- Request Begin --- \n")
    url, filepath, port = parse_input(sys.argv[1])
    print(f"Host: {url}")
    print("\n--- Sending Request ---\n")
    cookies, password, h2 = cookie_check(filepath, url, port)
    print("\n\n --- End Results Summarized ---")
    print(f'1. {h2}\n2. {password}')
    print("--- COOKIE LIST ---")
    [print(a + "\n") for a in cookies]
    if len(cookies) == 0:
        print("   No Cookies :(")
    else:
        print(f"Number of Cookies: {len(cookies)}")

main()