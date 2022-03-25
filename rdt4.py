#!/usr/bin/python3
"""Implementation of RDT4.0

functions: rdt_network_init, rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: CHENG LANG
Student No. : 3035396393
Date and version: 29/04/2021, v1
Development platform: Windows 10 (20H2)
Python version: 3.8.5
"""

import struct
import select
import socket
import random
import math

#some constants
PAYLOAD = 1000		#size of data payload of each packet
CPORT = 100			#Client port number - Change to your port number
SPORT = 200			#Server port number - Change to your port number
TIMEOUT = 0.05		#retransmission timeout duration
TWAIT = 10*TIMEOUT 	#TimeWait duration
MSG_FORMAT = 'BBHH' #format of header
ACK_TYPE = 11 #type no. of ACKs
DATA_TYPE = 12 #type no. of DATAs
BASE = 0 #window base of sender
N = 1 #no. of packets to send
MAX_SEQ = 256 #Sequence no 0 to 255
#store peer address info
__peeraddr = ()		#set by rdt_peer()
#define the error rates and window size
__LOSS_RATE = 0.0	#set by rdt_network_init()
__ERR_RATE = 0.0
__W = 1

#packet sequence numbers
s_seq = 0 #tracks the expected packet to send
r_seq = 0 #tracks the expected packet to receive
buffer = []

# last_ack_num = -1 #track the last ack


#internal functions - being called within the module
def __udt_send(sockd, peer_addr, byte_msg):
	"""This function is for simulating packet loss or corruption in an unreliable channel.

	Input arguments: Unix socket object, peer address 2-tuple and the message
	Return  -> size of data sent, -1 on error
	Note: it does not catch any exception
	"""
	global __LOSS_RATE, __ERR_RATE
	if peer_addr == ():
		print("Socket send error: Peer address not set yet")
		return -1
	else:
		#Simulate packet loss
		drop = random.random()
		if drop < __LOSS_RATE:
			#simulate packet loss of unreliable send
			print("WARNING: udt_send: Packet lost in unreliable layer!!")
			return len(byte_msg)

		#Simulate packet corruption
		corrupt = random.random()
		if corrupt < __ERR_RATE:
			err_bytearr = bytearray(byte_msg)
			pos = random.randint(0,len(byte_msg)-1)
			val = err_bytearr[pos]
			if val > 1:
				err_bytearr[pos] -= 2
			else:
				err_bytearr[pos] = 254
			err_msg = bytes(err_bytearr)
			print("WARNING: udt_send: Packet corrupted in unreliable layer!!")
			return sockd.sendto(err_msg, peer_addr)
		else:
			return sockd.sendto(byte_msg, peer_addr)

def __udt_recv(sockd, length):
	"""Retrieve message from underlying layer

	Input arguments: Unix socket object and the max amount of data to be received
	Return  -> the received bytes message object
	Note: it does not catch any exception
	"""
	(rmsg, peer) = sockd.recvfrom(length)
	return rmsg

def __IntChksum(byte_msg):
	"""Implement the Internet Checksum algorithm

	Input argument: the bytes message object
	Return  -> 16-bit checksum value
	Note: it does not check whether the input object is a bytes object
	"""
	total = 0
	length = len(byte_msg)	#length of the byte message object
	i = 0
	while length > 1:
		total += ((byte_msg[i+1] << 8) & 0xFF00) + ((byte_msg[i]) & 0xFF)
		i += 2
		length -= 2

	if length > 0:
		total += (byte_msg[i] & 0xFF)

	while (total >> 16) > 0:
		total = (total & 0xFFFF) + (total >> 16)

	total = ~total

	return total & 0xFFFF


#These are the functions used by appliation

def rdt_network_init(drop_rate, err_rate, W):
	"""Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability, packet corruption probability and Window size
	"""
	random.seed()
	global __LOSS_RATE, __ERR_RATE, __W
	__LOSS_RATE = float(drop_rate)
	__ERR_RATE = float(err_rate)
	__W = int(W)
	print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE, "\tWindow size:", __W)

def rdt_socket():
	"""Application calls this function to create the RDT socket.

	Null input.
	Return the Unix socket object on success, None on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	try:
		sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as emsg:
		print("Socket creation error: ", emsg)
		return None
	return sd

def rdt_bind(sockd, port):
	"""Application calls this function to specify the port number
	used by itself and assigns them to the RDT socket.

	Input arguments: RDT socket object and port number
	Return	-> 0 on success, -1 on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	try:
		sockd.bind(("",port))
	except socket.error as emsg:
		print("Socket bind error: ", emsg)
		return -1
	return 0

def rdt_peer(peer_ip, port):
	"""Application calls this function to specify the IP address
	and port number used by remote peer process.

	Input arguments: peer's IP address and port number
	"""
	######## Your implementation #######
	global __peeraddr
	__peeraddr = (peer_ip, port)



def rdt_send(sockd, byte_msg):
	"""Application calls this function to transmit a message (up to
	W * PAYLOAD bytes) to the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: (1) This function will return only when it knows that the
	whole message has been successfully delivered to remote process.
	(2) Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global BASE, s_seq, N, buffer, __peeraddr
	msg_len = len(byte_msg)  #length of message(file), ret value

	 # Count how many packets needed to send byte_msg
	N = num_of_packets(byte_msg)
	print("rdt_send(): sending %d packets" % N)
	#initializing
	packets_to_send = [None] * N 
	unacked_idx = 0 
	BASE = s_seq 


	#construct and send packets
	for i in range(N):
		data, byte_msg = cut_msg(byte_msg) #byte_msg being the remainder
		packets_to_send[i] = assemble_data(s_seq, data)
		try:
			__udt_send(sockd, __peeraddr, packets_to_send[i])
		except socket.error as emsg:
			print("rdt_send(): Socket send error: ", emsg)
			return -1
		print("rdt_send(): sent " + parse(packets_to_send[i]))

		s_seq = add_seq(s_seq, 1) #increment sender's seq

	rlist = [sockd]

	received_all_ACK = False
	while not received_all_ACK:
		rl, wl, xl = select.select(rlist, [], [], TIMEOUT)
		if rl: #if there is a packet
			for r_sock in rl:
				try:
					received_packet = __udt_recv(r_sock, 6 + PAYLOAD)
				except socket.error as emsg:
					print("rdt_send():  ", emsg)
					return -1
				print("rdt_send(): packet received", parse(received_packet))

				if is_corrupt(received_packet):
					print("rdt_send(): recived corrupt packet, ignored")
				elif has_type(received_packet, ACK_TYPE): #if a ACK is received
					if not is_in_between(received_packet, ACK_TYPE, BASE, BASE + N - 1):
						print("rdt_send(): ACK is not in range! ignored")
					
					#else if is within range and is not last
					elif is_in_between(received_packet, ACK_TYPE, BASE, BASE + N - 2):
						print("send(): range [%d, %d] -> accept ACK" % (BASE, BASE + N - 2))
						(message_type, recv_seq, chksum, payload_length), payload = unpack_msg(received_packet)

						#update the current unacked idx
						unacked_idx = max(sub_seq(recv_seq, BASE) + 1, unacked_idx)

					#return length of the msg if this is the last ACK
					elif is_in_between(received_packet, ACK_TYPE, BASE + N - 1, BASE + N - 1):
						return msg_len

				
				elif has_type(received_packet, DATA_TYPE):
					print("rdt_send(): received data "+ parse(received_packet))
					
					if has_expected_seq(received_packet, r_seq):
						#if the packet is not yet buffered, buffer it
						if received_packet not in buffer:
							buffer.append(received_packet)
							print("rdt_send(): buffered a data packet")
						# ACK the DATA pkt
						try:
							__udt_send(sockd, __peeraddr, assemble_ack(r_seq))
						except socket.error as emsg:
							print("send(): Error in sending ACK to received data: ", emsg)
							return -1
						print("rdt_send(): ACK[%d]" % r_seq)

						
					else:
                       # If not the expected data packet, ACK the packet with -1 seq
						try:
							__udt_send(sockd, __peeraddr, assemble_ack((sub_seq(r_seq, 1))))
						except socket.error as emsg:
							print("send(): Error in ACK-ing expected data: ", emsg)
							return -1
						print("send(): ! Buffer NOT expected (%d) -> sent ACK[""%d]" % (r_seq, sub_seq(r_seq, 1)))

		
		else:
			print("rdt_send():Timeout!, Retransmit the packets again" )
			for i in range(unacked_idx, N):
				try:
					__udt_send(sockd, __peeraddr, packets_to_send[i])
					print("rdt_send(): resending packet " + parse(packets_to_send[i]))
				except socket.error as emsg:
					print("Socket send error: ", emsg)
					return -1				


def rdt_recv(sockd, length):
	"""Application calls this function to wait for a message from the
	remote peer; the caller will be blocked waiting for the arrival of
	the message. Upon receiving a message from the underlying UDT layer,
    the function returns immediately.

	Input arguments: RDT socket object and the size of the message to
	received.
	Return  -> the received bytes message object on success, b'' on error

	Note: Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global r_seq, buffer
	#while the buffer is not empty, check if expected data is inside
	while buffer:
		received_packet = buffer.pop(0)  
		if has_expected_seq(received_packet, r_seq):
			r_seq = add_seq(r_seq, 1) # Increment expected sequence number to receive
			return unpack_msg(received_packet)[1]
	
	received_expected_packet = False
	while not received_expected_packet:  
		try:
			received_packet = __udt_recv(sockd, length + 6)
		except socket.error as emsg:
			print("rdt_recv(): Socket receive error: ", emsg)
			return -1
		print("rdt_recv(): received " + parse(received_packet))

		if is_corrupt(received_packet) or has_type(received_packet, ACK_TYPE):
			print("rdt_recv(): Received corrupted or ACK -> ignore")
		
		elif has_type(received_packet, DATA_TYPE):
			if has_expected_seq(received_packet, r_seq):
				try:
					__udt_send(sockd, __peeraddr, assemble_ack(r_seq))
				except socket.error as emsg:
					print("rdt_recv(): Error in ACK-ing expected data: ", emsg)
					return -1
				print("rdt_recv(): expected -> sent ACK[%d]" % r_seq)
				# Increment expected sequence number
				r_seq = add_seq(r_seq, 1)
				return unpack_msg(received_packet)[1]

			# If DATA is not expected
			else:
				try:
					__udt_send(sockd, __peeraddr, assemble_ack(sub_seq(r_seq, 1)))

				except socket.error as emsg:
					print("rdt_recv(): Error ACK-ing expected data: ", emsg)
					return -1
				print("rdt_recv(): NOT expected (%d) -> sent ACK[%d]" % (r_seq, sub_seq(r_seq, 1)))



def rdt_close(sockd):
	"""Application calls this function to close the RDT socket.

	Input argument: RDT socket object

	Note: (1) Catch any known error and report to the user.
	(2) Before closing the RDT socket, the reliable layer needs to wait for TWAIT
	time units before closing the socket.
	"""
	######## Your implementation #######
	global __peeraddr

	rlist = [sockd]  
	close_signal = False  

	while(not close_signal):
		#wait for TWAIT
		rl, wl, xl = select.select(rlist, [], [],TWAIT)  
		if rl: 
			for r_sock in rl:
				try:
					received_packet = __udt_recv(r_sock, 6 + PAYLOAD)
				except socket.error as emsg:
					print("rdt_close(): udt failed to receive packet: ", emsg)
				print("rdt_close(): contunuing data transmission")

				if not is_corrupt(received_packet): #ACK the uncorupt data packet
					(_, recv_seq, _, _), _ = unpack_msg(received_packet)
					try:
						__udt_send(sockd, __peeraddr, assemble_ack(recv_seq))
					except socket.error as emsg:
						print("rdt_close(): udt failed to send ACK: ", emsg)
					print("rdt_close(): finished ACKing last packet")
		else:  
			print("rdt_close(): nothing happened for 0.500 seconds")
			close_signal = True
			try:
				print("rdt_close(): Release the socket")
				sockd.rdt_close()
			except socket.error as emsg:
				print("rdt_close(): failed to close socket: ", emsg)




#given data, calculate the number of packets need to make
def num_of_packets(data):
	num_pkt = int(math.ceil(float(len(data))/PAYLOAD))  
	return num_pkt


#constructs a data packet
def assemble_data(seq, data):
	global DATA_TYPE, MSG_FORMAT
	Chksum = 0 #init checksum value
	data_size = len(data)
	message_format = struct.Struct(MSG_FORMAT)
	packet = message_format.pack(DATA_TYPE, seq, Chksum, socket.htons(data_size)) + data #assemble the packet first for checksum
	Chksum = __IntChksum(packet)
	data_packet = message_format.pack(DATA_TYPE, seq, Chksum, socket.htons(data_size)) + data 
	return data_packet

#ensure the msg being shorter than PAYLOAD
def cut_msg(byte_msg):
	if len(byte_msg) > PAYLOAD:
		data = byte_msg[0:PAYLOAD]
		remaining = byte_msg[PAYLOAD:]
	else:
		data = byte_msg
		remaining = None
	return data, remaining

def unpack_msg(msg):
	global MSG_FORMAT
	msg_size = struct.calcsize(MSG_FORMAT)
	(msg_type, seq,chksum, payload_length), payload = struct.unpack(MSG_FORMAT, msg[:msg_size]), msg[msg_size:]
	return (msg_type, seq, chksum, socket.ntohs(payload_length)), payload 

#returns whether a packet is corrupt
def is_corrupt(packet):
	global MSG_FORMAT
	(msg_type, seq, chksum, payload_length), payload = unpack_msg(packet)
	#extract message from packet
	message = struct.Struct(MSG_FORMAT).pack(msg_type, seq, 0, socket.htons(payload_length)) + payload
	#check sum
	checksum = __IntChksum(message)
	#if the re computed checksum not equal to chksum comes with packet, the packet is corrupted, return true
	return checksum != chksum

#check whether the packet has the given packet type, and whether it has seq between lower bound and upper bound
def is_in_between(pkt, pkt_type, low, high):
    (recv_type, recv_seq, _, _), _ = unpack_msg(pkt)
    if recv_seq < low: 
        recv_seq += MAX_SEQ
    return recv_type == pkt_type and low <= recv_seq <= high

#check whether a packet has type pkt_type
def has_type(pkt, pkt_type):
	(recv_type, _, _, _), _ = unpack_msg(pkt)
	return recv_type == pkt_type

#construct an ACK with designated seq number
def assemble_ack(seq):   
	global ACK_TYPE, MSG_FORMAT
	message_format = struct.Struct(MSG_FORMAT)
	checksum = 0 
	intermediate = message_format.pack(ACK_TYPE, seq, checksum, socket.htons(0)) + b'' #construct an intermediate packet with checksum set to 0, ACK regarded as no size
	checksum = __IntChksum(intermediate)
	ack_packet = message_format.pack(ACK_TYPE, seq, checksum, socket.htons(0)) + b''
	return ack_packet

#check whether a packet as sequence number seq
def has_expected_seq(packet, seq):
	(message_type, pkt_seq, chksum, payload_length), payload = unpack_msg(packet)
	return seq == pkt_seq


#message parser
def parse(msg):
    if is_corrupt(msg):
        return -1
    msg_str = ""
    (msg_type, seq_num, checksum, payload_len), payload = unpack_msg(msg)
    if msg_type == DATA_TYPE:
        msg_str += "DATA"
    elif msg_type == ACK_TYPE:
        msg_str += "ACK"
    msg_str += "[%d]" % seq_num
    if payload_len > 0:
        msg_str += " of size %d" % payload_len
    if 0 < payload_len <= 20:
        msg_str += " -> " + str(payload)
    return msg_str

#sequence number computations, implementing wrap-around
def add_seq(a, b):
    return (a + b) % MAX_SEQ
def sub_seq(a, b):
    return (a - b + MAX_SEQ) % MAX_SEQ


