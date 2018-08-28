#! /usr/bin/python
from scapy.all import wrpcap, Ether, IP, TCP
from collections import deque
import logging
import argparse
import random
import os


class CorruptPatternFileError(Exception):
    pass


class DummyDumpCreator(object):

    PATTERN_SIZE_LENGTH = 2
    DUMMY_DST_IP = "127.0.0.1"
    DUMMY_DST_PORT = 12345
    DEFAULT_DUMP_NAME = "dummy_dump.pcap"
    DEAFULT_MAX_PATTERNS = 0
    DEFAULT_CONCENTRATION_FACTOR = 0.2

    def __init__(self, concentration_factor=DEFAULT_CONCENTRATION_FACTOR, 
            max_patterns=DEAFULT_MAX_PATTERNS, dump_name=DEFAULT_DUMP_NAME):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.patterns = []
        self.unused_char = None
        self.concentration_facotor = concentration_factor
        expansion_factor = 1 - self.concentration_facotor
        self.extra_bytes = int((1.0 + expansion_factor) ** (1.0 + 7.0 * expansion_factor))
        self.max_patterns = max_patterns
        self.dump_name = dump_name

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
        packets = []
        count_in = 0
        count_out = 0
        for _ in xrange(num_packets):
            patterns = self.patterns
            random.shuffle(patterns)
            if self.max_patterns:
                patterns = patterns[:self.max_patterns]
            patterns = deque(patterns)
            packet = Ether() / IP(dst=self.DUMMY_DST_IP) / TCP(dport=self.DUMMY_DST_PORT)
            payload = ""
            while len(patterns) and len(payload) < 1536:
                cur_pat = patterns.pop()
                payload += cur_pat
                payload += self.unused_char
                payload += os.urandom(self.extra_bytes)
                count_out += self.extra_bytes 
                count_in += len(cur_pat)
            packet = packet / payload
            ratio = float(count_in) / float(count_in + count_out)
            packets.append(packet)
        print("Inside patterns: {}\nOutside patterns: {}\nIn/Out Ratio: {}".format(count_in, count_out, ratio))
        wrpcap(self.dump_name, packets)


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