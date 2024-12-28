Covert Timing Channel that exploits Idle Period Between Packet Bursts using DNS [Code: CTC-IPPB-DNS]

Contributors:

Alperen Taşdelen - 2521987
Emre Safa Baltacı - 2580314

Note: The project is built on a different branch named phase2. Please change the branch before looking to the project.
Github repository link: https://github.com/AlperenTasdelen/Ceng435Phase1.git

A covert timing channel is a method of transmitting information secretly by manipulating timing characteristics in a communication system, making the transmission challenging to detect and analyze.

In this project, Idle Periods Between Packet Bursts using the DNS protocol is used.

The sender encodes data by varying idle times between bursts of DNS queries. 

The receiver decodes the message by analyzing these intervals, interpreting specific timing patterns as binary data.
- Short idle is represented as 0
- Long idle is represented as 1

MyCovertChannel represents the covert channel implementation referencing CovertChannelBase

MyCovertChannel includes two functions: send() and receive().

send(): Generates 16 byte random message including '.' at the end as a stopping character.
- Uses two parameters: short_idle and long_idle represented in config.json
- Dynamically adjusts the idle period between bursts to encode each bit.
- Sends DNS packets to the target IP (172.18.0.2) in bursts.
- Logs the generated message and transmission details into a file specified in the log_file_name parameter of config.json.

receive(): Uses scapy.sniff to capture packets from the sender.
- Measures the time intervals between bursts of DNS packets, And implements short_idle + tolerance as 0 and long_idle + tolerance as 1
- Decodes each character given by sender. 
- Stops when the stopping character is detected.
- Logs the reconstructed message and timing information into a file specified in the log_file_name parameter.
- Each short_idle, long_idle, tolerance and log_file_name are represented in config.json file also.

Parameters:
- All short_idle, long_idle, burst_size, and tolerance are adjustable to suit network conditions and optimize capacity.
- The parameters can be fine-tuned for performance and resilience against network delays.
- A tolerance parameter allows the receiver to handle minor network delays without decoding errors.

Covert Channel Capacity and Speed Calculation

- Covert Channel transmission speed depends on the given character idle representation.
- Formula: Capacity = Message Length / Total Transmission Rate
- Message length is fixed at 128 in this experiment.
- Total Transmission rate depends of the message kind
    - If full of short idles are used -> 128 / 128 * 0.1 = 10 bits per second
    - If full of long idles are used -> 128 / 128 * 0.3 = 3.3 bits per second
    - On average idle usage -> 128 / 128 * 0.2 = 5 bits per second

In the experiment, transmisson time is calculated as 30 seconds. 
Experiment results: 128 / 30 = 4.3 bits per second

Channel capacity is restricted on long and short idle sizes. 

How to use the experiment

1) Write docker compose up -d in the main folder. This creates sender and receiver containers.
2) Make two terminals each mimics sender and receiver
3) Write docker exec -it sender bash and write docker exec -it receiver bash on the other entering inside the container
4) Write cd ../app on both terminals, and you enter the programs.
5) Write make receive on receiver openning the sniffer
6) Write make send on sender creating the random message and sending to the receiver
7) You can look at the receiver terminal interpreting the bytes one by one

- Result messages are written on Example_UDPTimingInterarrivalChannelReceiver.log and Example_UDPTimingInterarrivalChannelSender.log
- You can write make compare to one of the terminals to see whether the message is correctly transferred or not.

Notes
- The tolerance parameter in the receiver helps account for small timing variations, but excessive delays or jitter can still result in decoding errors.
- Each packet burst encodes only a single bit. Increasing the number of bits per burst could improve capacity but risks making the channel more detectable.
- Efforts were made to randomize certain aspects of packet transmission to minimize detectability.
- Determining optimal values for short_idle, long_idle, and tolerance was iterative and required multiple tests to balance capacity and reliability.
- The implementation includes robust logging mechanisms for both sender and receiver.