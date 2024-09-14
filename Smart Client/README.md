# smartClient

smartClient is a smart client web tool that, given the url of a web server will find out:
<ol>
        <li>Whether or not the server supports http2</li>
        <li>The cookie name, and any relative information about the cookies the server will use</li>
        <li>Whether or not the requested web page is password protected</li>
</ol>

## Usage
To compile and run the program,
<ol>
    <li>Open a bash terminal,</li>
    <li>In the terminal, in the folder where smartClient.py is kept, write: </li>
</ol>

```
python3 smartClient.py url
```

### Input
smartClient will accept inputs of the following formats:
<ul>
    <li>http://example.com/path</li>
    <li>example.com/</li>
    <li>example.com</li>
    <li>www.example.com:80/</li>
    <li>www.example.com</li>
    <li>http://example.com</li>
</ul>

### Output
Upon the running of this program, the process of the client requesting and receiving information will be printed out*. A summary of the information found out will appear at the very bottom of the result.

For example**:
```
oeafolaranmi@linux203:~/CSC361/A1$ python3 smartClient.py uvic.ca                    
--- Request Begin --- 

Host: uvic.ca

--- Sending Request ---

GET / HTTP/1.1
Host: uvic.ca


--- Request Sent ---

 --- Response Received---

HTTP/1.0 302 Moved Temporarily
Location: https://www.uvic.ca/
Server: BigIP
Connection: Keep-Alive
Content-Length: 0

 --- BODY HIDDEN ---

 --- End of Response ---
 --- Response Code:  HTTP/1.0 302 Moved Temporarily
 --- Redirection Needed ---

 --- Redirecting to www.uvic.ca ---
     GET / HTTP/1.1
     Host: www.uvic.ca



 --- Request Sent --- 

 --- Response Received --- 
     HTTP/1.1 200 OK
 --- (Most of Header hidden for readability) ---

 --- BODY HIDDEN ---

 --- End of Response ---
 --- Response Code:  HTTP/1.1 200 OK
 --- Password Not Needed ---
 --- Information Found!! ---


 --- End Results Summarized ---
     1. http2 is NOT supported
     2. This website is NOT password protected

--- COOKIE LIST ---
Set-Cookie: PHPSESSID=dcu1m1v6sfekccvk4bq4pe95hm; path=/; secure; HttpOnly; SameSite=Lax

Set-Cookie: uvic_bar=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=.uvic.ca; secure; HttpOnly

Set-Cookie: (Hidden for readability)

Set-Cookie: (Hidden for readability)

Set-Cookie: (Hidden for readability)

Number of Cookies: 5
```

*The Request Body has been hidden as it is not useful for our client's purpose

**In the example, certain parts of the output have been hidden for readbility purposes

