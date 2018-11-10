#! /usr/bin/python
from scapy.all import wrpcap, Ether, IP, TCP
from collections import deque
import logging
import argparse
import random
import socket
import os


class CorruptPatternFileError(Exception):
    pass


class DummyDumpCreator(object):

    PATTERN_SIZE_LENGTH = 2
    DUMMY_DST_IP = "10.0.0.2"
    DUMMY_DST_PORT = 12345
    DEFAULT_DUMP_NAME = "dummy_dump.pcap"
    DEAFULT_MAX_PATTERNS = 0
    DEFAULT_CONCENTRATION_FACTOR = 0.2

    def __init__(self, concentration_factor=DEFAULT_CONCENTRATION_FACTOR, 
            max_patterns=DEAFULT_MAX_PATTERNS, dump_name=DEFAULT_DUMP_NAME):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.patterns = []
        self.unused_char = None
        self.set_concentrarion(concentration_factor)
        self.max_patterns = max_patterns
        self.dump_name = dump_name
        self.count_in = 0
        self.count_out = 0
        self.packets = []

    def set_concentrarion(self, concentration):
        self.concentration_facotor = concentration
        expansion_factor = 1 - self.concentration_facotor
        self.extra_bytes = int((1.0 + expansion_factor) ** (1.0 + 7.0 * expansion_factor))

    def read_patterns(self, filename):
        """
        Reads pattern with the MCA2 binary patters format
        """
        with open(os.path.realpath(filename), "rb") as patt_f:
            while True:
                size = patt_f.read(self.PATTERN_SIZE_LENGTH)
                if not size:
                    break
                if len(size) < self.PATTERN_SIZE_LENGTH:
                    raise CorruptPatternFileError
                size = ord(size[0]) << 8 | ord(size[1])
                self.logger.debug("pattern size = %d", size)
                pattern = patt_f.read(size)
                self.logger.debug("pattern = %s", pattern)
                self.logger.debug("length of pattern = %s", len(pattern))
                if len(pattern) == size:
                    self.patterns.append(pattern)
                else:
                    raise CorruptPatternFileError
            self.unused_char = self.find_char_not_in_patterns()
    
    def find_char_not_in_patterns(self):
        """ 
        Finds a  plausible delimiter, acharacter not used in patterns
        Hopefully one exists
        """
        used = [False] * 256
        for patt in self.patterns:
            for char in patt:
                used[ord(char)] = True
        return chr(used.index(False))

    def create_dump(self, num_packets):
        self.packets = []
        self.count_in = 0
        self.count_out = 0
        for _ in xrange(num_packets):
            patterns = self.patterns[:]
            random.shuffle(patterns)
            if self.max_patterns:
                patterns = patterns[:self.max_patterns]
            patterns = deque(patterns)
            packet = Ether() / IP(dst=self.DUMMY_DST_IP) / TCP(dport=self.DUMMY_DST_PORT)
            payload = ""
            max_payload = 1500 - len(packet)
            while len(patterns) and len(payload) < max_payload:
                cur_pat = patterns.pop()
                payload += cur_pat[:min(len(cur_pat), max_payload - len(payload))]
                if len(patterns) and len(payload) + self.extra_bytes + 1 < max_payload:
                    payload += self.unused_char
                    payload += os.urandom(self.extra_bytes)
                self.count_out += self.extra_bytes 
                self.count_in += len(cur_pat)
            packet = packet / payload
            self.packets.append(packet)

    def write_to_dump(self):
        ratio = float(self.count_in) / float(self.count_in + self.count_out)
        print("Inside patterns: {}\nOutside patterns: {}\nIn/Out Ratio: {}".format(self.count_in, self.count_out, ratio))
        wrpcap(self.dump_name, self.packets)

    def gen_payload(self, size):
        self.count_in = 0
        self.count_out = 0
        #start
        payload = ""
        if not self.concentration_facotor:
            payload = os.urandom(size)
        else:
            while len(payload) < size:
                patterns = self.patterns[:]
                random.shuffle(patterns)
                if self.max_patterns:
                    patterns = patterns[:self.max_patterns]
                patterns = deque(patterns)
                payload_size = len(payload)
                while len(patterns) and len(payload) - payload_size < 1500:
                    cur_pat = patterns.pop()
                    payload += cur_pat
                    # If last pattern to be added, dont add random bytes and separator.
                    if len(patterns):
                        payload += self.unused_char
                        payload += os.urandom(self.extra_bytes)
                        self.count_out += self.extra_bytes 
                        self.count_in += len(cur_pat)
            ratio = float(self.count_in) / float(self.count_in + self.count_out)
            print("Inside patterns: {}\nOutside patterns: {}\nIn/Out Ratio: {}".format(self.count_in, self.count_out, ratio))
        with open("temp_payload", "w+") as f_payload:
            f_payload.write(payload)
        return payload

    def gen_packet(self):
        self.count_in = 0
        self.count_out = 0
        #start
        patterns = self.patterns[:]
        random.shuffle(patterns)
        if self.max_patterns:
            patterns = patterns[:self.max_patterns]
        patterns = deque(patterns)
        packet = Ether() / IP(dst=self.DUMMY_DST_IP) / TCP(dport=self.DUMMY_DST_PORT)
        payload = ""
        while len(patterns) and len(payload) < 1500:
            cur_pat = patterns.pop()
            payload += cur_pat[:min(len(cur_pat), 1500 - len(payload))]
            # If last pattern to be added, dont add random bytes and separator.
            if len(patterns) and len(payload) + self.extra_bytes + 1 < 1500:
                payload += self.unused_char
                payload += os.urandom(self.extra_bytes)
                self.count_out += self.extra_bytes 
            print len(payload)
            self.count_in += len(cur_pat)
        return packet / payload

    def send_spam(self, dest_addr, concentration, size):
        self.set_concentrarion(concentration)
        payload = self.gen_payload(size)
        print "Generated spam {}, ready to send".format(len(payload))
        raw_input("Press ENTER to continue...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(dest_addr)
        sock.sendall(payload)
        sock.close()


def parse_args():
    arg_parse = argparse.ArgumentParser(
        description="Creates a dump with given patterns concentration")
    arg_parse.add_argument("patterns", type=str,
        help="The patterns binary file path")
    arg_parse.add_argument("num_packets", type=int,
        help="Number of packets to create")
    arg_parse.add_argument("--max_patterns", type=int, default=DummyDumpCreator.DEAFULT_MAX_PATTERNS,
        help="Max number of patterns to use in single packet")
    arg_parse.add_argument("--concentration", type=float, default=DummyDumpCreator.DEFAULT_CONCENTRATION_FACTOR,
        help="Max number of patterns to use in single packet")
    arg_parse.add_argument("--dump_name", type=str, default=DummyDumpCreator.DEFAULT_DUMP_NAME,
        help="The output dump pcap file path")
    arg_parse.add_argument("--debug", "-d", action="store_true",
        help="Print debug information")
    return arg_parse.parse_args()

if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    logger = logging.getLogger("")
    if 0 <= args.concentration <= 1:
        creator = DummyDumpCreator(
            concentration_factor=args.concentration,
            max_patterns=args.max_patterns,
            dump_name=args.dump_name
        )
        creator.read_patterns(args.patterns)
        creator.create_dump(args.num_packets)
    else:
        logger.error("Bad concentration %d", args.concentration)