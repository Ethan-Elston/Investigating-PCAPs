# Investigating/Analyzing PCAPs

## Steps

Beginning Notes:

	- First off, what is a PCAP?

	- PCAPs (Packet Captures) are files that store network traffic captured from a network interface. In cybersecurity and SOC (Security Operations Center) analysis, PCAPs are used for:
		○ Incident Investigation
		○ Threat hunting
		○ Malware analysis
		○ Network Forensics
		○ IDS/IPS validation

	- PCAPs usually contain all network traffic that was captured during a specific timeframe.  They can be configured to capture only specific protocols, sources, or types of traffic, depending on the tool and settings used.



Blue Team Labs Online:

	- I'm going to re-use a retired lab from Blue Team Labs Online (BTLO) to learn how to analyze and investigate PCAPs properly

	- So I'll need to head over to the BTLO Challenges tab and filter for retired challenges
		○ These are the only ones I can do and post online because they are not active challenges, and it won't disrupt the competitive community

	- I'll be doing the lab called "Network Analysis - Web Shell"

![image](https://github.com/user-attachments/assets/c78618d2-2fb2-4a72-bb72-576dbab1d70d)

	- If I click on the challenge, I'll get an overview of the BTLOs official scenario. 
		○ I also can see submission requirements needed in order to complete this challenge

![image](https://github.com/user-attachments/assets/6815f1c8-64fa-4612-a9ce-7116e7534e16)
![image](https://github.com/user-attachments/assets/1051d320-dbd3-4159-94d1-b21427714033)

	- Notice the scenario. What does 'Local to Local port scanning' mean, and why would someone be interested in that in the first place?

	- Local-to-local port scanning means scanning ports on the same device or within the same local network
		○ Self-scan: Checking open ports on the same machine ('nmap localhost')
		○ LAN-scan: Scanning other devices in the same network

	- However, in short, someone would be interested in this because an internal host SHOULD NOT be scanning another host UNLESS it's an authorized host that is used for vulnerability scanning

	- In part 1 of this lab, I downloaded Wireshark and ran through the basics
		○ Since I'm able to use any tool I wish, I'll use this tool for the investigation


Using Wireshark to investigate general information about the PCAP:

	- At the top of the challenge, there is an option to download a packet capture, I need to download that file

![image](https://github.com/user-attachments/assets/b9c8f67b-9dbd-4f9c-a992-f1e81bc8ccae)

	- I get a warning message that explains that the file includes real malware
		○ I'm doing this in my home lab VM
		○ I have already taken baseline snapshots

	- Now I need to go into file explorer and extract that downloaded malware file using the given password 

![image](https://github.com/user-attachments/assets/a954d3b7-8eb4-4323-9969-9d00e8baeef7)

	- I need to right-click the file and select 'Extract All'
		○ Then I can enter the password

![image](https://github.com/user-attachments/assets/77ef1ebb-911b-46fb-8257-19b49a08f79d)

	- Once its successfully extracted, I'll need to open the file in Wireshark
		○ I do this my right-clicking the file and the option to open in Wireshark is presented

![image](https://github.com/user-attachments/assets/231c7cf6-5e78-4480-8909-9d107b28f43f)

	- As you can see the file is now in Wireshark

	- I'll need to look for the answers to the challenge questions. However, I'm going to use some of the tips I learned in Part 1 to see what information I can get from the PCAP alone.

	- So I need to navigate to the 'Statistics' tab at the top, and select the first option 'Capture File Properties'

![image](https://github.com/user-attachments/assets/a23fada9-7f69-4051-bcee-ee08ff15f84c)

	- I can see that the first packet was taken on the 7th of February in 2021 at 10:31:22; it finished at 10:46:31
		○ The packet capture was about 15 minutes long

	- This is a good practice in a real-world scenario because now I can ask and verify with the client that the time frame is correct

	- Something along the lines of:

	"The PCAP you provided me is within this <time frame> is that correct?"
	
	- Imagine you spend your valuable time evaluating an incorrect PCAP…

	- Now let's look at the information provided from another option in the Statistics tab; 'Protocol Hierarchy'
		○ If you (the reader) is unsure what these do, go back to Part 1 for a brief overview

![image](https://github.com/user-attachments/assets/b8811e23-13f9-42b8-88ac-e53610a93a8f)

	- There is a large amount of protocols within this PCAP

	- I notice there is a couple familiar protocols:
		○ SSH
		○ DNS
		○ HTTP
		○ SMB
		○ Etc. 

	- The protocols  I listed are "more" important than the others because these have potential lateral movement opportunities
		○ Lateral movment refers to an attacker moving from one system to another within a network after gaining initial access

	- These are also "clear-text" protocols, which means I can read the exchange between a protocol like HTTP and see what is happening
		○ I could potentially identify malware being downloaded

	- But in the case of this scenario, I am not sure yet that this PCAP involves malware, so let's keep gathering information

	- The next option I need to look at is in the Statistics tab as well; 'Conversations'
		○ I'll need to select the IPv4 tab
		○ Then I'll sort it by bytes by clicking the bytes column at the top

![image](https://github.com/user-attachments/assets/20f4e9be-1c59-4a36-bbc4-a7bf047404ef)

	- Filtering it by bytes will show the top communicators 
		○ I'll keep tabs on the top 2 conversations
		○ 10.251.96.4  -> 10.251.96.5
		○ 170.20.10.5 -> 172.20.10.2

![image](https://github.com/user-attachments/assets/7cb835fc-66f5-48d9-bbe8-1a0b00ed26c5)

	- Next, I'll look at the TCP tab

![image](https://github.com/user-attachments/assets/d2c5624a-0154-4574-8f30-369f151fc8f5)

	- Immediately, there is something odd about this

	- The source IP (10.251.96.4) is hitting A LOT of ports toward 10.251.96.5

	- Notice the source port: 41675
		○ It’s the same port through the entire list

	- Because the source port is the same, this is indicative of a port scan
		○ These source ports should be unique per connection attempt 
		○ If it's the same, then that means scanning activity 

	- I'm going to try and find more information in the rest of the conversation, I scrolled until I finally came across a different source port other than 41675

![image](https://github.com/user-attachments/assets/41994f06-3415-4f3b-8c52-fc51183f0583)

	- The source ports are now different, but now .4 is hitting .5 on port 80

	- Now I'm curious… if I scroll back up and look at port 41675 hitting port 80. I notice something else very odd. 

![image](https://github.com/user-attachments/assets/2cff441a-5461-4b25-8a67-85432fd39b93)

	- The bytes are different than the rest
		○ But I do notice one port with the same bytes, just a bit below port 80 on the list
		○ Port 22 also has the same amount of bytes

![image](https://github.com/user-attachments/assets/0f089797-80f1-4080-849c-0b00eca0ef2c)

	- What this likely means is that the destination host (10.251.96.5), had responded with a synac flag
		○ The other ports did not respond because those ports are closed

	- I can infer that .5 has port 80 and 22 open

	- If I scroll down even further, I can see a break in the pattern of destination port 80

![image](https://github.com/user-attachments/assets/3c49dbef-418e-4616-8afe-35f1d6f3284c)

	- I see one with a destination port of 4422, but this time the source and destination addresses are different
		○ 10.251.96.5 -> 10.251.96.4

	- It seems to be .5 calling back to .4 
		○ Source port is 48994
		○ Destination port is 4422

	- I have no idea what this is, but it's worth taking note of

	- Below that, I also see destination external IP addresses 34.122. and 35.224.

	- I also see an internal address (172.20.10.5) going to .2
		○ No idea what these are, but it's worth taking notes

	- A good practice is to jot down anything that is suspicious that could be of potential use later


Looking for Gold in Wireshark:

	- Now it's time to start investigating with some intention

	- Before I begin investigating, the 'Time' column in the packet list pane is in a form that is not easy to read

![image](https://github.com/user-attachments/assets/ad402d28-03d6-476a-8c92-ea51355d5aa0)

	- I can change this in the 'View' tab at the top
		○ Then I just need to switch the time display format to one that I like

![image](https://github.com/user-attachments/assets/aa9222ce-d9b1-43be-842a-d5c0d4edd9d4)

	- In the packet list pane, I can see HTTP traffic beginning with packet 14

![image](https://github.com/user-attachments/assets/ca1416da-e952-4d75-8f75-1a4ad2a12415)

	- It's a GET request. A GET request is an HTTP method used to retrieve data from a server. It requests a resource (like a webpage, API data, or file) without modifying it

	- GET requests are specific to HTTP/HTTPS. Other protocols (like FTP, SSH, or SMB) have their own request methods for retrieving data
		○ Used in HTTP/HTTPs (primarily for web browsing and APIs)
		○ Sent via URLs (GET /index.html)
		○ No body in the request just headers and queries parameters
		○ Data is visible in the URL

	- If I right-click the packet, and then select the 'Follow' option from the drop-down menu, I have two options:
		○ TCP Stream and a
		○ HTTP Stream

![image](https://github.com/user-attachments/assets/8bdb4f72-f30a-481a-9754-aae4c629b214)

	- Clicking on these will show the communication between the client and the server

	- What the difference between TCP and HTTP stream?
		○ In TCP stream some of the content in the server responses just doesn't make sense and it's hard to read
		○ HTTP makes more sense, and you can follow along with what's happening easier

![image](https://github.com/user-attachments/assets/c2e343e8-8bb4-48fe-b419-7ea6aafb0ec4)

	- Red is client requests

	- Purple is server responses

	- You can filter at the bottom of this window, if you only want to view client requests or server responses. Or you can just view the entire conversation.

	- If I scroll down, I can see the software version and address of the server

![image](https://github.com/user-attachments/assets/72ee6849-4214-4354-8a39-fe58fa5af910)

	- Notice that it's the same address from earlier (172.20.10.2), we viewed earlier in the conversation tab

	- So now we know that 172.120.10.2 is this Ubuntu server



	- At this point in the investigation, I'll want to keep continuously scrolling the main packet list pane, trying to find anything that catches my eye
		○ For instance, I noticed a POST request; packet 38

	- A POST request is an HTTP method used to send data to a server (form submissions, API request, uploading files)
		○ It modifies data on the server
		○ Data is sent in the request body (not visible in the URL)
		○ More secure than GET for sending sensitive information

	- POST is specific to HTTP/HTTPS and is used in web communications and APIs to send data to a server

	- It's worth finding out what was entered

![image](https://github.com/user-attachments/assets/d7ae2d60-8305-4483-bf4f-b19d5b7c930a)

	- I'll use the 'Follow' and 'HTTP Stream' to look at the conversation between the client/server

![image](https://github.com/user-attachments/assets/5da26573-b9e3-4dc3-bb5a-14b574cd6120)

	- As you can I found a login
		○ Username = admin
		○ Password = Admin%401234

	- Special character are encoded in the password
		○ If you see % symbols it's URL-encoded
		○ URL encoding always follows a specific pattern: %XX, where XX is a two-digit hexadecimal number representing an ASCII character.

	- Passwords are usually encoded for obfuscation, it just hides the raw password

	- When you see special characters, you can just google a simple URL decoder, and paste the encoded character

![image](https://github.com/user-attachments/assets/e0c8a475-eb69-402b-b7b7-ed7ab90c6c21)

	- So the password = Admin@1234


	- In the future, I need to understand the differences between HTTP and HTTPS
		○ This includes both of its request methods such as it's get requests or post requests
		○ As well as the status codes

	- When visiting sites, be on the lookout for what protocol the site is using
		○ If it's HTTP, avoid logging in if you can


	- Once I kept scrolling I eventually was presented with the traffic from 10.251.96.4 and .5

![image](https://github.com/user-attachments/assets/46601b73-21d4-48df-99ba-636269fa6b54)

	- But I want to be able to view the source and destination port in the packet list pane

	- I'll need to click the 'Edit' tab at the top and the select 'Preferences' at the bottom of the drop-down menu
		○ This will open the preferences window

![image](https://github.com/user-attachments/assets/0bb81b03-d5dc-48ab-8794-41b441a324b0)

	- Once there I'll need to select columns and then select the + sign at the bottom to add a new column

	- Once added I'll need to name the column and then select the column type
		○ So named them both: "Source Port" and "Destination Port"
		○ Then I selected source port and destination port as the type
		○ The source and destination port should now be added

![image](https://github.com/user-attachments/assets/5a177e85-db23-4c8c-8a25-8607cdcbc44f)

	- Select 'Apply' and 'Ok' before exiting the preferences window

![image](https://github.com/user-attachments/assets/35a31f35-0294-4a39-9d45-20d1cfb075bb)

	- As you can see these columns are now added

	- But I want to view them more easily and I want the columns to show up more to the left before the others
		○ to move the columns you simply drag the columns to the location you desire

![image](https://github.com/user-attachments/assets/d9432869-00cc-4e54-b894-864a0036fd55)

	- They are now positioned accordingly 

	- The first port scan attempt was on packet 117
		○ This happened on February 7th at 16:33:06

	- If I scroll down I can see a SYN ACK on Port 80 and Port 20

	- This is the 3-way handshake and an indicator that data transmission had begun between them

![image](https://github.com/user-attachments/assets/1bae328d-7af8-4737-831b-bd62a6789343)


	- I want to see the last packet scanned, so I'll need to keep scrolling

![image](https://github.com/user-attachments/assets/1a7eeab1-f8e5-42a9-9bfa-734cb451ef33)

	- The last packet scanned was 2166
		○ This happened at 16:33:06 (wow the scan occurred in less than a second)

	- Notice packet 2172 above
		○ We know that the 3-way handshake has occurred. Now they are actually communicating
		○ This is actually the first communication from .4 to .5 on port 80
		○ "GET / HTTP/1.1" means that this is an HTTP request, so it indicates client initiation (.5 is likely a web server)
		○ Let's follow the HTTP stream
		○ Nothing interesting 

	- There might be another POST request if we keep scrolling…

	- Sure enough

![image](https://github.com/user-attachments/assets/5306467c-0a2d-412a-bcf8-1522b7933afc)

	- Let's follow it

![image](https://github.com/user-attachments/assets/4e8f8929-a87e-4ca9-9a49-4c0670149b98)

	- Found some login information, %27 is used for both the username and password
		○ %27 decoded is a single quote '

	- This is a slow process of slowly investigating anything that is suspicious

	- I found another GET request on packet 2215
		○ I'll need to follow it

	- Is there anything that correlates with the last GET request I found on packet 2172?
		○ If we go back to that packet from earlier, the user agent is:

![image](https://github.com/user-attachments/assets/43fefd73-0cc3-44d7-93a2-2e4fed80fc5d)

	- For packet 2215, the user agent is:

![image](https://github.com/user-attachments/assets/36c25497-2724-4de1-8605-cb14796cf293)

	- I need to take note of this. This is very important.
		○ The first use of this user-agent is at 16:34:05

	- 'gobuster' is a tool that can crawl directories 

	- Blue teaming is like solving a complex puzzle, trying to fit the pieces together and tie connections between findings. I CANNOT stress this enough, pay attention and take notes of anything that might be of use later






	- Now I know there is definitely something fishy going on. But there's so much data… how can I go through it more efficiently?

	- There is a ton of information to sort through in the packet list pane. However I can create display filters to help find information that is potentially more valuable

	- There are tons of "cheat-sheets" for Wireshark that you can use on the internet to help find information faster

	- However you can also implement these filters manually by right-clicking and applying filters



	- I'll click a random '404- Not Found' packet and then view the "Byte pane" in the bottom left corner (see below)

![image](https://github.com/user-attachments/assets/24f4c3c7-e826-4117-ac22-8258b3c88e81)
![image](https://github.com/user-attachments/assets/be943824-c261-4918-a201-49362bd007a1)

	- I can expand the application layer (HTTP), and then expand the HTTP/1.1 404

![image](https://github.com/user-attachments/assets/adf84567-5d0a-4345-9b9a-72aad34123b6)

	- Here I can see the status code (above)

	- If I right click, I have two options:
		○ I can apply as a filter, which immediately will filter information for status code 404
		○ Or I can prepare as a filter, which will add this to the filter bar at the top

	- This is super helpful if you don't know how to write queries

	- If I select 'Prepare as filter', I should be able to see it at the top in the filter bar. I can also edit this bar, for other status codes. 
		○ Let's say I want to edit for the 200 status code instead of 404
		○ I'll just delete 404 and type 200

![image](https://github.com/user-attachments/assets/d5a29246-905e-4a79-8aa7-83f6299fc533)

	- There we go now it can filter for the 200 status code

	- But I don't want just any 200 status codes, I want these status codes from the 10.251.96.5 host
		○ But I don't know queries and I wouldn't know how to format it for both filters
		○ What do I do?

	- Well now with that same packet, I can just go to layer 3 in the Byte panel and expand it
		○ I need to look for the source address
									
![image](https://github.com/user-attachments/assets/54ca44ac-0e0e-4ab9-a8db-9b7c037fca1d)
![image](https://github.com/user-attachments/assets/7e72a9b1-1b3c-4efe-81ec-461fbb9189db)

	- If I right-click it, I can 'prepare as filter' and then select 'and Selected' to add it to any queries already in the filter bar

	- The filter bar should be immediately changed

![image](https://github.com/user-attachments/assets/d82e116e-7e9c-4187-bf9a-669c61d9301f)

	- Then I just need to hit enter

	- So why am I even filtering for a 200 status code on the 10.251.96.5 host?

	- A 200 status code in HTTP means "OK", the request was successful, and the server returned the requested source.
		○ This is important because it confirms successful communication…
		○ The client (10.251.96.4) successfully connected, sent a request, and got a valid respone
		○ This is bad news if they found anything 



	- Now we have a list of requests that the .5 web server replied to
		○ These are basically saying "hey! Yea this exists!"

![image](https://github.com/user-attachments/assets/76cf38dc-0798-4f53-8b23-2bf7f8cf0259)

	- So now that we have a view of successful responses from 10.251.95.5, I need to shift focus to the length

![image](https://github.com/user-attachments/assets/ae831997-db9d-463d-ac4a-3c3bb9683a22)

	- Notice that the lengths are all almost in the same range of 500- 700
		○ Except for two, which are much larger than the rest
		○ Packets 13894, and 7725

	- This indicates that the server had responded with something large

	- If I follow the HTTP stream on packet 7725
		○ The User-Agent is gobuster, which is not good

![image](https://github.com/user-attachments/assets/3ce629bc-fcdb-4834-9880-8f7471549ed2)

	- I need to scroll further to see if this gobuster found a directory or something of that nature

![image](https://github.com/user-attachments/assets/efb7d1a1-00f5-4ba4-8daa-584bc09ba5c5)

	- The information I see indicates a lot of responses.

![image](https://github.com/user-attachments/assets/24c2ae98-864a-42c1-8888-ef4ccfa7fd97)

	- The file name is info.php
		○ The server responded with 200 OK
		○ This is basically the server saying 'hey I exist'

	- So the user-agent gobuster has PHP info, and can also likely found the version of PHP at the bottom (7.2)

	- This means whoever requested this, now knows the PHP version. They can try and exploit this particular version or application

	- A PHP file is a script written in PHP (Hypertext Preprocessor), a server-side scripting language used for web development. 


	- Now I'll follow packet 13894, the other packet

![image](https://github.com/user-attachments/assets/09f64eb5-c6b9-4b47-99ff-e23bdcd89672)
![image](https://github.com/user-attachments/assets/d9816109-ee5e-4ec3-8272-b1291f6cd02a)

	- It seems like we get the same PHP info, but the user-agent is different this time

	- This could indicate that someone manually visited the directory

	- So how long did gobuster take to do it's scans?
		○ Well I know that there is a bunch of GET requests

	- If I keep scrolling in the packet pane, I can see when the last GET request was made. Packet 13661.

![image](https://github.com/user-attachments/assets/cbd1c165-9d85-4bab-b588-b63f5833e7c9)

	- I'm not very interested in the 172.20.10.2 or 172.20.10.5 address traffic, probably a test server.
		○ I can see it browsing, etc.
		○ But I know that 10.251.96.4 was performing the port scanning so I'll move on

	- Suddenly after scrolling some more I start seeing 10.251.96.4 traffic again. 

![image](https://github.com/user-attachments/assets/20f34362-e617-486e-bb1c-94abbaec1ddc)

	- I can see the attacker viewing an info.php

	- I then found a packet that includes "upload"

![image](https://github.com/user-attachments/assets/d1a81eff-fcc9-4a9f-ac26-ace1906a8663)

	- So I know now that there is an upload directory
		○ This is very important because this means that on the web server, there is likely an area where someone can upload a file to the web server
		○ If I follow the HTTP stream, I can actually see that they were viewing this upload
 
	- Is there a post request for anything uploaded to that directory? (indicating something was uploaded successfully)

	- There is a post request… packet 13979

![image](https://github.com/user-attachments/assets/cbeee81c-04be-4539-8ce8-6571fae32f5e)

	- If I follow the HTTP stream I can see that the user-agent has changed again to sqlmap

![image](https://github.com/user-attachments/assets/d6fa7f3b-6f51-4135-a786-1899fbe50af0)

	- This is VERY important
		○ It happened at 16:36:17

	- SQLmap is a tool that performs automated SQL attacks
		○ We need to take note of the time that it occurred

	- They tried to login using 'user' and 'pass'


	- Let's keep scrolling

	- I find another weird post request, packet 14060

![image](https://github.com/user-attachments/assets/a60b88d1-7875-471b-b49f-d047d55a67bf)

	- If I follow this post request, we can see that this is clearly some kind of SQL attack
		○ It's encoded
		○ We need to post this into our URL decoder asap

![image](https://github.com/user-attachments/assets/768efff0-434d-4b97-acf1-1334e0d71dfa)
![image](https://github.com/user-attachments/assets/39a4a1de-397f-4598-8927-65b36d2c9260)

	- We can then see clearly what they were trying to do (see at the bottom)
		○ We can also see they were testing for XSS

	- I can see at the end their objective is to open up a shell and read the file /etc/passwd

	- After going back to the main packet pane, I see a lot more POST requests
		○ This is most likely SQL map attacking the server

	- The last post request from SQL map seems to have happened at 16:37:28. Packet 15978



	- Now it's worth trying to see POST request from the IP 10.251.96.4
		○ This will find anything the attacker uploaded to the web server
		○ They did visit an upload directory, so it's very possible they uploaded something

	- Let's check to see if they uploaded anything
		○ I'll use my instructors query to find this 
		○ 'http.request.method == POST && ip.addr == 10.251.96.4'

	- There is a lot of post requests that aren't really that interesting, except… for the very last post request.
		○ There was a post request for upload.php at 16:40:39
		○ If we follow this we can see that there is a file named "dbfunctions.php"

![image](https://github.com/user-attachments/assets/fc78f924-c4c2-467d-bc8e-9ccf9c366652)
![image](https://github.com/user-attachments/assets/8dda04f5-85f7-4ba1-8b25-14df110bddcf)

	- The referrer says editprofile.php

![image](https://github.com/user-attachments/assets/a6347f62-31d0-4993-ae29-f6c601bb3684)

	- The "Referer" header in an HTTP request indicates that the previous webpage that directed the user (or request) to the current request. So in simple terms, this means the upload action was likely triggered from that page (Upload Profile Picture button on 'editprofile.php')

	- So if we picture this from the attackers point of view, they clicked on edit profile, and then selected a button called "upload" and then started uploading the dbfunctions.php file
		○ When I scrolled down I can see that they "submitted" it
		○ I also see that it was successfully uploaded 


	- If I keep scrolling down I can see a GET function for '/uploads/dbfunctions.php?cmd=id' . Packet 16134 at 16.40.51
		○ Issued their first command 'id'
		○ I followed it and can see the attacker's UID

![image](https://github.com/user-attachments/assets/ee847a9f-62fe-434f-bba5-533be071220d)

	- Another GET request for 'whoami'. Packet 16144 at 16:40:56
		○ Second command

![image](https://github.com/user-attachments/assets/9f759f3f-3100-49b5-ada8-8c720c47fded)

	- I  get another interesting GET request. Packet 16201 at 16:42:35
		○ If I follow it, it seems to be encoded

![image](https://github.com/user-attachments/assets/f12e9ab1-8105-4805-a63d-4ef5e97ab607)
![image](https://github.com/user-attachments/assets/379e44f9-9d04-4d50-9452-0e080f08e1c8)
![image](https://github.com/user-attachments/assets/d0653834-0329-404e-a5f0-adfeac620ab2)

	- If we decode it we can see that they are running python with an import and some sort of connection for 10.251.96.4 on port 4422
		○ "Import" refers to loading a Python module (a separate file of code) into another script
		○ When you run Python with an import, you're telling Python to execute a script that imports another module
		○ They are trying to call for a subprocess  '/bin/sh'

	- The next logical step is to see if there was any call back towards this 10.4 address on port 4422
		○ A "call back" in this context refers to a reverse connection where the target system (10.251.96.4) established an outbound connection back to the attacker's system on port 4422
		○ If there is that might suggest a reverse shell or backdoor
		○ We need to go back to our main packet list view and look below the python request

	- Right below the GET pythong request I can see an initial connection attempt
		○ Then we get our 3-way handshake

![image](https://github.com/user-attachments/assets/07b87207-df06-4146-99f7-a272507a11a6)

	- So there was a callback towards the IP of 10.251.96.4 on port 4422
		○ It happened at 16:42:45

	- I need to follow the TCP stream this time on the initial connection attempt

![image](https://github.com/user-attachments/assets/d36c5de5-4a10-47f6-809a-8dc4bd747223)

	- This is bad
		○ It's a successful web shell

	- The attacker clearly now has hands-on keyboard access to this web server
		○ It seems the attacker is mainly doing some discovery commands (whoami, cd, ls)
		○ Trying to find directories that exist
		○ They did in fact try to remove db

	- If this was a real-case some sort of persistence would of likely occurred
		○ Such as creating a cron-job
		○ Modifying SSH keys
		○ Or even spinning up crypto miners to mine crypto





Ending Notes:

	- Webserver:
		○ IP: 10.251.96.5
		○ Username: www-data
		○ Hostname: bob-appserver

	- Port-Scan Activity
		○ Start: 2021-02-07 16:33:06 (UTC)
		○ End: 2021-02-07 16:33:06 (UTC)
		○ Source/Port: 10.251.96.4 : 41675
		○ Destination/Port: 10.251.96.5 (22/80 opened)

	- Applications Used by 10.251.96.4
		○ Gobuster 3.0.1
			§ Start time: 2021-02-07 16:34:05
			§ End time: 2021-02-07 16:34:06
		○ Sqlmap 1.4.7
			§ Start time: 2021-02-07 16:36:17
			§ End time: 2021-02-07 16:37:28

	- Successful Web Shell upload
		○ Name: dbfunctions.php
		○ Start: 2021-02-07 16:40:39
		○ Source: 10.251.96.4
		○ Destintion: 10.251.96.5

	- Commands ran by 10.251.96.4 via webshell
		○ 'id'
		○ 'whoami'
		○ Python script for callback

	- Successful callback to 10.251.96.4: 4422 via TCP reverse shell from 10.251.96.5
		○ Start: 2021-02-07 16:42:35

	- Commands ran from the webserver via reverse TCP shell
		○ 'bash -I'
		○ 'whoami'
		○ 'cd'
		○ 'ls'
		○ Python and 'rm db'

	- Last observed activity from 10.251.96.4 was on 2021-02-07 16:45:56








	- Answers to the questions:

![image](https://github.com/user-attachments/assets/7fbc52c7-15e3-439f-8448-487b692591ae)

	- I figured out the port range by going to the statistics tab on Wireshark and selecting 'Conversation'
		○ Just like how we sorted the conversations by bytes earlier, I sorted them by ports
		○ Then I just scrolled to see the starting port and the last port

	- When the source port is the same for a scan, that means it's most likely a TCP SYN scan

	- Remember where the attacker went to upload the webshell, it was editprofile.php

	- The parameter used was cmd. I know this because if I go back to the first packet that began its first command (packet 16134). It calls the webshell, then it gets cmd=id

![image](https://github.com/user-attachments/assets/0a11c2c5-85ac-4481-919c-654e4e6f5d69)
