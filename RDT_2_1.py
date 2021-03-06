import Network_2_1 as Network
import argparse
from time import sleep
import hashlib
import time
import os

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ack_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S, ack=0):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.ack = ack


    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        ack = int(byte_S[Packet.length_S_length+Packet.seq_num_S_length + Packet.checksum_length : Packet.length_S_length+Packet.seq_num_S_length + Packet.checksum_length + Packet.ack_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length + Packet.ack_length: ]
        return self(seq_num, msg_S, ack)


    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)

        # convert ack into a byte field:
        ack_S = str(self.ack).zfill(self.ack_length)

        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(ack_S) + len(self.msg_S)).zfill(self.length_S_length)

        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S+ack_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + ack_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        ack_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length + Packet.checksum_length : Packet.length_S_length+Packet.seq_num_S_length + Packet.checksum_length + Packet.ack_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.ack_length + Packet.checksum_length :]
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S + ack_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

    def is_ack(self):
        return self.ack != 0


def debug(string):
    # print(string)
    pass

class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    rec_num = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        debug("Increment seq_num in send")
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())

    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration

    def rdt_2_1_send_ack(self, ack):
        p = Packet(self.seq_num, '', ack)
        self.network.udt_send(p.get_byte_S())


    def send_packet(self, mssg):
        try:
            self.network.udt_send(mssg)
        except:
            debug("Connection must have been sent: Client is finished")
            # becauase we are lazy
            os._exit(0)

    def recieve_packet(self):
        try:
            return self.network.udt_receive()
        except:
            debug("Packet must have been sent: Other is finished")
            os._exit(0)


    def rdt_2_1_send(self, msg_S):
        packetSent = False
        p = Packet(self.seq_num, msg_S)
        self.send_packet(p.get_byte_S())

        while not packetSent:
            # send the packet:
            # Wait for an ack packet to make it back:
            gotPack = False
            while not gotPack:
                byte_S = self.recieve_packet()
                self.byte_buffer += byte_S
                #check if we have received enough bytes
                if(len(self.byte_buffer) < Packet.length_S_length):
                    continue
                # extract length of packet
                length = int(self.byte_buffer[:Packet.length_S_length])
                if len(self.byte_buffer) >= length:
                    gotPack = True
            # check to make sure that the correct ack was given:
            if Packet.corrupt(self.byte_buffer[0:length]):
                # Do things for corrupt packet:
                debug("Response is corrupt. Resending...")
                self.send_packet(p.get_byte_S())
            else:
                rec = Packet.from_byte_S(self.byte_buffer[0:length])
                if rec.msg_S == 'nak':
                    debug("Is NAK. Resending")
                    debug("Expected: " + str(p.seq_num))
                    debug("Recieved: " + str(rec.ack))
                    self.send_packet(p.get_byte_S())
                elif rec.msg_S == 'ack' and rec.ack == p.seq_num:
                    debug("Recived ack: " + str(rec.ack))
                    debug("Our seq: " + str(p.seq_num))
                    debug("Packet sent sucessfully")
                    self.seq_num += 1
                    packetSent = True
                    # break;
                else:
                    if rec.msg_S == 'ack' and rec.ack < p.seq_num:
                        debug("Send: Recieved dupe ack")
                        # ack for something we already established, ignore
                        pass
                    elif rec.seq_num < self.rec_num:
                        # its a message? Re-send confirmation
                        # resend the ack:
                        debug("Recieved dupe:")
                        debug(rec.msg_S + "\n")
                        debug("Resending ack " + str(rec.seq_num))
                        answer = Packet(rec.seq_num, 'ack', rec.seq_num)
                        self.send_packet(answer.get_byte_S())
                        debug("Resending packet:")
                        self.send_packet(p.get_byte_S())
                    elif not rec.is_ack() and rec.seq_num == self.rec_num:
                        debug("Next packet recieved. Packet must have been sent sucessfully")
                        self.seq_num += 1
                        packetSent = True
                    else:
                        debug("Don't know what to do.")
                        debug(rec.msg_S)
                        debug("Ack num: " + str(rec.ack))
                        debug("Rec seq num: " + str(rec.seq_num))
                        debug("OUr rec num: " + str(self.rec_num))
                        debug("Our seq num: " + str(self.seq_num))
            self.byte_buffer = self.byte_buffer[length:]




    def rdt_2_1_receive(self):
        ret_S = None
        byte_S = self.recieve_packet()
        self.byte_buffer += byte_S
        cur_seq = self.rec_num
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            if Packet.corrupt(self.byte_buffer[0:length]):
                # Do things for corrupt packet:
                debug("Recieve: Packet is corrupt")
                answer = Packet(cur_seq, 'nak',-1)
                self.send_packet(answer.get_byte_S())
            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                # check seq number:
                if p.is_ack():
                    debug("Recieved ack packet")
                    debug(p.ack)
                    # ignore the packet:
                    # continue
                elif p.seq_num == self.rec_num:
                    # packet is correct!
                    # send ack:
                    debug("Incrementing rec num")
                    answer = Packet(p.seq_num, 'ack', p.seq_num)
                    self.send_packet(answer.get_byte_S())
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.rec_num = self.rec_num + 1
                else:
                    if self.rec_num > p.seq_num:
                        debug("Recieved duplicate ack")
                        # re-send ack:
                        answer = Packet(p.seq_num, 'ack', p.seq_num)
                        self.send_packet(answer.get_byte_S())
                    debug("Sequence number is incorrect")
                    debug("Expected: " + str(self.rec_num))
                    debug("Recieved: " + str(p.seq_num))
            #remove the packet bytes from the buffer
            debug("Receive: Shortening buffer...")
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration


    def rdt_3_0_send(self, msg_S):
        packetSent = False
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())
        currentTime = time.clock()
        timeout = .001

        while not packetSent:
            # send the packet:
            # Wait for an ack packet to make it back:
            gotPack = False
            while (not gotPack) and ((time.clock()-currentTime) < timeout):
                byte_S = self.recieve_packet()
                self.byte_buffer += byte_S
                #check if we have received enough bytes
                if(len(self.byte_buffer) < Packet.length_S_length):
                    continue
                # extract length of packet
                length = int(self.byte_buffer[:Packet.length_S_length])
                if len(self.byte_buffer) >= length:
                    gotPack = True
            if not gotPack:
                self.network.udt_send(p.get_byte_S())
                currentTime = time.clock()
                debug("timeout...!")
                continue
            debug("Got packet")
            # check to make sure that the correct ack was given:
            if Packet.corrupt(self.byte_buffer[0:length]):
                # Do things for corrupt packet:
                debug("Response is corrupt. Resending...")
                self.send_packet(p.get_byte_S())
            else:
                rec = Packet.from_byte_S(self.byte_buffer[0:length])
                if rec.msg_S == 'nak':
                    debug("Is NAK. Resending")
                    debug("Expected: " + str(p.seq_num))
                    debug("Recieved: " + str(rec.ack))
                    self.send_packet(p.get_byte_S())
                elif rec.msg_S == 'ack' and rec.ack == p.seq_num:
                    debug("Recived ack: " + str(rec.ack))
                    debug("Our seq: " + str(p.seq_num))
                    debug("Packet sent sucessfully")
                    self.seq_num += 1
                    packetSent = True
                    # break;
                else:
                    if rec.msg_S == 'ack' and rec.ack < p.seq_num:
                        debug("Send: Recieved dupe ack")
                        # ack for something we already established, ignore
                        pass
                    elif rec.seq_num < self.rec_num:
                        # its a message? Re-send confirmation
                        # resend the ack:
                        debug("Recieved dupe:")
                        debug(rec.msg_S + "\n")
                        debug("Resending ack " + str(rec.seq_num))
                        answer = Packet(rec.seq_num, 'ack', rec.seq_num)
                        self.send_packet(answer.get_byte_S())
                        debug("Resending packet:")
                        self.send_packet(p.get_byte_S())
                    elif not rec.is_ack() and rec.seq_num == self.rec_num:
                        debug("Next packet recieved. Packet must have been sent sucessfully")
                        self.seq_num += 1
                        packetSent = True
                    else:
                        debug("Don't know what to do.")
                        debug(rec.msg_S)
                        debug("Ack num: " + str(rec.ack))
                        debug("Rec seq num: " + str(rec.seq_num))
                        debug("OUr rec num: " + str(self.rec_num))
                        debug("Our seq num: " + str(self.seq_num))
            self.byte_buffer = self.byte_buffer[length:]

    def rdt_3_0_receive(self):
        return self.rdt_2_1_receive()


if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
