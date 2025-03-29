# Part-1: Installing Wireshark and learning basics

## Steps

	- Wireshark is a network protocol analyzer

	- It lets you capture and interactively browse the traffic running on a computer network

	- It does have limitations:
		○ If a PCAP > 500mb it starts to bog down the application

	- There are ways around it however
		○ Wireshark comes with programs such a t-shark as well
		○ 'tshark.exe'

	- T-shark can read that 500mb PCAP and filter for things that I'm interested in
		○ Let's say we are interested in a destination IP for all traffic going to 8.8.8.8
		○ You can run a filter on t-shark and output it into another PCAP

	- This makes it so you can use Wireshark to now read that PCAP and have a much more manageable size


Downloading Wireshark:

	- First I need to go to the website, then select the download button

	- Since I'm on a Windows machine, I'll need to select the 'Windows x64 Installer' option
	
![image](https://github.com/user-attachments/assets/9820344a-7974-4792-a7e0-6f815db7f6e7)

	- I'll need to open the setup file in file explorer and then go through the prompts

	- I also need to make sure that Tshark is included in the download, as you can see, it is checked

![image](https://github.com/user-attachments/assets/45715fe0-d2d1-42bb-a7b4-d326807d03e6)

	- Once wire-shark is finished installing and I open the application, I'll get a "capture screen"

![image](https://github.com/user-attachments/assets/09689033-32af-4522-a6e9-815d5a23e8ce)

	- This capture screen will display all of the network adapters that are attached to my computer

	- If you double click on one of these adapters, it will start capturing traffic based on that network adapter
		○ I'll click the adapter for loopback addresses for this example

	- This is on one of my VMs so it might not behave as if it were on my real computer

![image](https://github.com/user-attachments/assets/575e6816-4330-485e-a6c0-8eeeaed4b692)

	- As you can see there is some traffic that was captured. If I wanted to stop the capturing, I would need to click the red square at the top

	- At the top you can see the menu, this has:
		○ File
		○ Edit
		○ View
		○ Go
		○ Capture
		○ Analyze
		○ And lots more

	- Beneath the menu, there is a filter

![image](https://github.com/user-attachments/assets/02c40dc8-7eab-4a6e-8090-5cbcb53a0f3a)

	- You could filter for 'ip', 'tcp', etc. 

	- Then underneath the filter is the actual packet list pane
		○ It's a high level view of all the packets that are going or "captured" through the wire

![image](https://github.com/user-attachments/assets/68effc46-33c1-4f34-bf4b-b3e317184f5f)

	- Below the packet list is the packet "BYTE" pane

![image](https://github.com/user-attachments/assets/698db3b6-0790-40d8-a108-98409827cd75)

	- It's sorted by OSI layer 
		○ At the top is Layer 1, "Frame 1…"
		○ The layer 2, "Null/Loopback"
		○ Layer 3, "Internet Protocol Version 4…"
		○ Layer 4, "User Datagram Protocol…"
		○ Layer 5, "Simple Service Discovery Protocol"

	- To the right of this pane, is the packets "BYTES" pane

![image](https://github.com/user-attachments/assets/47409ba9-896a-4035-932d-8fb5423e811e)

	- This pane shows you the hex 
		○ This looks straight into the data and gives you all of the raw information 


Analyzing PCAPs and "Quick Win" Strategies:

	- When analyzing PCAPs, some of these options below can give you a "quick win" when trying to identify malicious traffic

	- When you open up a file to analyze a PCAP file, click the 'Statistics' tab at the top to find out more information on the PCAP

![image](https://github.com/user-attachments/assets/2b987590-5a27-4f01-bc2e-8eccbd978459)

			- As you can see there are a lot of options here

	- Notice the first option 'Capture File Properties'
		○ This will show you the:
			§ Name
			§ Length of the file
			§ Hash
			§ The format of the file
			§ The encapsulation type
			§ The time of the first packet and last packet, as well as the duration of the capture

	- This is important information, for example; let's say you're handed a PCAP and your client/employer says that the PCAP should be starting from this date and ending at this time. You can use the capture file properties to confirm whether or not the PCAP you have is correct or not

![image](https://github.com/user-attachments/assets/ecf31ae3-d426-4f6a-857a-18af3b2fe915)

	- Another good option is the "Protocol Hierarchy" 
		○ This will display a list of protocols that exist in the PCAP

![image](https://github.com/user-attachments/assets/b0dc3ebf-152b-4f38-9bd0-0139a8267974)

	- If I right-click one of these protocols, such as TCP at the bottom, I am presented with a couple options
		○ Notice 'Apply as Filter' and 'Prepare as Filter"

	- 'Apply as filter' option would make Wireshark immediately filter for this protocol

	- 'Prepare as Filter' would move this filter to the display filter, in the filter bar at the top

![image](https://github.com/user-attachments/assets/d488cbe9-8410-452c-9fce-4130265fb219)

	- If I select 'Apply as filter' it will automatically filter through the traffic 

![image](https://github.com/user-attachments/assets/67e5e20e-1adb-4ffd-a3a6-2a61c79e2204)

	- As you can see above it automatically filtered for TCP traffic

	- Another good option is 'Conversations"
		○ This will show you the conversations between one host and another

	- If I select the IPv4 protocol tab at the top, I can see the conversation

![image](https://github.com/user-attachments/assets/baec00ee-4594-4afc-aad6-72435867bda3)

	- You can sort it by bytes to make sure that the highest communicator is at the top

![image](https://github.com/user-attachments/assets/ab91cc4d-8fb7-425a-a733-ae2a64e224b0)


	- This could potentially provide a quick win if we notice a high transfer outbound to an IP that is malicious


	- The 'Endpoints' option will tell you what endpoints exist in this PCAP
		○ If I select the IPv4 protocol tab, I can see my IP address

![image](https://github.com/user-attachments/assets/6b8503a9-e264-4e01-8b67-f2ecf4d67da4)

	- If there was one or more hosts in this capture file, we would see multiple IP addresses


	- If you select the file tab at the top, you'll notice that Wireshark as the ability to export objects 
		○ You can export something from HTTP, SMB, etc. 

	- Let's say you are a user that clicks on a phishing link
		○ That link is hosting a malicious file on that web server 
		○ If that website is running a HTTP protocol

	- If we have a full packet capture running, we can actually extract that file that was downloaded and then prepare or perform more analysis



	- To fully understand the rest of Wireshark capabilities I would like to learn how to perform analysis on a PCAP that actually resembles a real PCAP. I'll do this in the next part. 
