#!/usr/bin/python3
"""Implementation of RDT3.0

functions: rdt_network_init(), rdt_socket(), rdt_bind(), rdt_peer()
           rdt_send(), rdt_recv(), rdt_close()

Student name: CHENG Lang
Student No. : 3035396393
Date and version: 04/04/2020, v2
Development platform: Windows 10 (20H2)
Python version: 3.8.5
"""
import struct
import select
import socket
import random


#some constants
PAYLOAD = 1000		#size of data payload of the RDT layer
CPORT = 100			#Client port number - Change to your port number
SPORT = 200			#Server port number - Change to your port number
TIMEOUT = 0.05		#retransmission timeout duration
TWAIT = 10*TIMEOUT 	#TimeWait duration
MSG_FORMAT = 'BBHH' #format of header

ACK_TYPE = 11 #type no. of ACKs
DATA_TYPE = 12 #type no. of DATAs
#store peer address info
__peeraddr = ()		#set by rdt_peer()
#define the error rates
__LOSS_RATE = 0.0	#set by rdt_network_init()
__ERR_RATE = 0.0
#packet sequence numbers
s_seq = 0 #tracks the expected packet to send
r_seq = 0 #tracks the expected packet to receive

buffer = []
last_ack_num = -1 #track the last ack

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

def rdt_network_init(drop_rate, err_rate):
	"""Application calls this function to set properties of underlying network.

    Input arguments: packet drop probability and packet corruption probability
	"""
	random.seed()
	global __LOSS_RATE, __ERR_RATE
	__LOSS_RATE = float(drop_rate)
	__ERR_RATE = float(err_rate)
	print("Drop rate:", __LOSS_RATE, "\tError rate:", __ERR_RATE)


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
	"""Application calls this function to transmit a message to
	the remote peer through the RDT socket.

	Input arguments: RDT socket object and the message bytes object
	Return  -> size of data sent on success, -1 on error

	Note: Make sure the data sent is not longer than the maximum PAYLOAD
	length. Catch any known error and report to the user.
	"""
	######## Your implementation #######
	global PAYLOAD, __peeraddr, s_seq, last_ack_num, buffer
	# limiting msg length to PAYLOAD
	if (len(byte_msg) > PAYLOAD):
		msg = byte_msg[0:PAYLOAD]
	else:
		msg = byte_msg
	
	#assemble the data packet to be sent
	pkt = assemble_data(s_seq, msg)

	try:
		length = __udt_send(sockd, __peeraddr, pkt)
	except sockd.error as emsg:
		print("Socket send error: ", emsg)
		return -1
	print("rdt_send: Sent one message of size %d" % length)

	received_expected_ACK = False
	rlist = [sockd]
	while not received_expected_ACK:
		#first wait for the ACK
		rl, wl, xl = select.select(rlist, [], [], TIMEOUT)
		if rl: 
			for r_sock in rl:
				try: 
					packet_size = 1006 #The length of header: Type(1) + Seq(1) + Chksum(2) + PAYLOAD(2) = 6
					received_packet = __udt_recv(r_sock, packet_size)
				except socket.error as emsg:
					print("Socket udt recv error: ", emsg)
					return -1
					#if the packet is corrupted
				if is_corrupt(received_packet):
					print("rdt_send(): received a corrupted packet")
				elif is_expected_ACK(received_packet, 1-s_seq): 
					print("rdt_send(): Received the unexpected ACK")
				elif is_expected_ACK(received_packet, s_seq):
					s_seq = s_seq^1 #xor flips sequence number, seq only has values 1 and 0
					print("rdt_send(): Received the expected ACK")
					return length - 6 #return the size of payload
				#receiving data packets
				else:
					print("I am expecting an ACK packet, but received a DATA packet.")
					print("Peer sent me a new DATA packet!")
					if received_packet not in buffer:
						buffer.append(received_packet)

					(message_type, data_seq, chksum, payload_length), payload = unpack_msg(received_packet)
					try:
						# (message_type, pkt_seq, chksum, payload_length), payload = unpack_msg(packet)
						__udt_send(sockd, __peeraddr, assemble_ack(data_seq))
					except socket.error as emsg:
						print("Socket send ACK ERROR: ", emsg)
						return -1
					print("rdt_send(): ACKed Data %d" % data_seq)
					last_ack_num = data_seq #update ack num

		else:
			#timeout logic
			print("rdt_send():Timeout!, Retransmit the packet %d again" % s_seq)
			try:
				length = __udt_send(sockd, __peeraddr, pkt)
			except sockd.error as emsg:
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
	global PAYLOAD, __peeraddr, r_seq, last_ack_num, buffer
	#while the buffer is not empty, check if expected data is inside
	while buffer:
		received_data_packet = buffer.pop(0)
		if (is_expected_data(received_data_packet, r_seq)):
			print("Got an expected packet ")
			r_seq = r_seq^1
			return unpack_msg(received_data_packet)[1]
		
	received_expected_packet = False
	while not received_expected_packet:
		try:
			received_packet = __udt_recv(sockd, 6 + PAYLOAD)
		except sockd.error as emsg:
				print("rdt_recv(): Socket receive error: ", emsg)
				return b''

		# Send old ACK if packet is corrupt
		if is_corrupt(received_packet):
			print("rdt_recv(): Received a corrupted packet, expecting packet %d" % r_seq)
			old_ack = assemble_ack(1-r_seq)
			try:
				__udt_send(sockd, __peeraddr, old_ack)
			except socket.error as emsg:
				print("rdt_recv(): failed to send old ACK: ", emsg)
				return b''
		#also send old ACK if packet doesn't have the right seq
		elif has_expected_seq(received_packet, 1-r_seq):
			print("rdt_recv(): Received an unexpected packet, expecting packet %d" % r_seq)
			old_ack = assemble_ack(1-r_seq)
			try:
				__udt_send(sockd, __peeraddr, old_ack)
			except socket.error as emsg:
				print("rdt_recv(): failed to send old ACK: ", emsg)
				return b''
		#send ACK when receives an expected packet
		elif has_expected_seq(received_packet, r_seq):	
			print("rdt_recv(): Received a message of size %d" % len(received_packet))
			(_), payload = unpack_msg(received_packet)
			try:
				__udt_send(sockd, __peeraddr, assemble_ack(r_seq))
			except socket.error as emsg:
				print("rdt_recv(): failed to send ACK: ", emsg)
				return b''
			
			print("rdt_recv(): ACK%d sent" % r_seq)
			last_ack_num = r_seq
			r_seq = r_seq^1

			return payload


def rdt_close(sockd):
	"""Application calls this function to close the RDT socket.

	Input argument: RDT socket object

	Note: (1) Catch any known error and report to the user.
	(2) Before closing the RDT socket, the reliable layer needs to wait for TWAIT
	time units before closing the socket.
	"""
	######## Your implementation #######
	global last_ack_num, __peeraddr

	rlist = [sockd]
	close_signal = False

	while (not close_signal):
		#wait for TWAIT
		rl, wl, xl = select.select(rlist, [],[], TWAIT)
		if rl:
			for r_sock in rl:
				try:
					received_packet = __udt_recv(r_sock, 6 + PAYLOAD)
				except socket.error as emsg:
					print("rdt_close(): udt failed to receive packet: ", emsg)
				print("rdt_close(): contunuing data transmission")

				if not is_corrupt(received_packet) and is_expected_data(received_packet, last_ack_num):
					try:
						__udt_send(sockd, __peeraddr, assemble_ack(last_ack_num))
					except socket.error as emsg:
						print("rdt_close(): udt failed to send ACK: ", emsg)
					print("rdt_close(): finished ACKing last packet")
		else:
			print("rdt_close(): nothing happened for 0.500 seconds")
			close_signal = True
			try:
				print("rdt_close(): Release the socket")
				sockd.close()
			except socket.error as emsg:
				print("rdt_close(): failed to close socket: ", emsg)

#construct a data packet
def assemble_data(seq, data):
	global DATA_TYPE, MSG_FORMAT
	Chksum = 0 #init checksum value
	data_size = len(data)
	message_format = struct.Struct(MSG_FORMAT)
	packet = message_format.pack(DATA_TYPE, seq, Chksum, socket.htons(data_size)) + data #assemble the packet first for checksum
	Chksum = __IntChksum(packet)
	data_packet = message_format.pack(DATA_TYPE, seq, Chksum, socket.htons(data_size)) + data 
	return data_packet

#construct an ACK with designated seq number
def assemble_ack(seq):   
	global ACK_TYPE, MSG_FORMAT
	message_format = struct.Struct(MSG_FORMAT)
	checksum = 0 
	intermediate = message_format.pack(ACK_TYPE, seq, checksum, socket.htons(0)) + b'' #construct an intermediate packet with checksum set to 0, ACK regarded as no size
	checksum = __IntChksum(intermediate)
	ack_packet = message_format.pack(ACK_TYPE, seq, checksum, socket.htons(0)) + b''
	return ack_packet

def unpack_msg(msg):
	global MSG_FORMAT
	msg_size = struct.calcsize(MSG_FORMAT)
	(msg_type, seq,chksum, payload_length), payload = struct.unpack(MSG_FORMAT, msg[:msg_size]), msg[msg_size:]
	return (msg_type, seq, chksum, socket.ntohs(payload_length)), payload 

#checks whether a packet is corrupted
def is_corrupt(packet):
	global MSG_FORMAT
	(msg_type, seq, chksum, payload_length), payload = unpack_msg(packet)
	#extract message from packet
	message = struct.Struct(MSG_FORMAT).pack(msg_type, seq, 0, socket.htons(payload_length)) + payload
	#check sum
	checksum = __IntChksum(message)
	#if the re computed checksum not equal to chksum comes with packet, the packet is corrupted, return true
	return checksum != chksum

#check whether a packet as sequence number seq
def has_expected_seq(packet, seq):
	(message_type, pkt_seq, chksum, payload_length), payload = unpack_msg(packet)
	return seq == pkt_seq

#check whether a packet is the ACK with the expected sequence number
def  is_expected_ACK(packet, seq):
	global ACK_TYPE
	(message_type, pkt_seq, chksum, payload_length), payload = unpack_msg(packet)
	return message_type == ACK_TYPE and has_expected_seq(packet, seq)

#check whether a packet is the DATA with the expected seq number
def is_expected_data(packet, seq):
    global DATA_TYPE
    (message_type, pkt_seq, chksum, payload_length), payload = unpack_msg(packet)
    return message_type == DATA_TYPE and seq==pkt_seq

