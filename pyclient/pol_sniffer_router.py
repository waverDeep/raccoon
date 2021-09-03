#!/usr/bin/env python3
channel_interval = 2500
mesh_interval = 0.7
pol_num = 4

server_addr = 'http://192.168.50.125:8904'
hole = '3'
cc_name = 'test_cc'
##############################################################################
#
#      Copyright (c) 2018, Raccon BLE Sniffer
#      All rights reserved.
#
#      Redistribution and use in source and binary forms, with or without
#      modification, are permitted provided that the following conditions are
#      met:
#      
#      # Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      # Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following disclaimer
#        in the documentation and/or other materials provided with the
#        distribution.
#      # Neither the name of "btlejack2" nor the names of its
#        contributors may be used to endorse or promote products derived from
#        this software without specific prior written permission.
#      
#      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##############################################################################

import argparse
import os
import queue
import serial
import signal
import sys
import threading
import time
import json
from serial.tools.list_ports import comports
from pcap import *
from air_to_hci import *
import requests

# tags from packet.h
TAG_DATA = 0
TAG_MSG_RESET_COMPLETE = 0x40
TAG_MSG_CONNECT_REQUEST = 0x41
TAG_MSG_CONNECTION_EVENT = 0x42
TAG_MSG_CONN_PARAM_UPDATE = 0x43
TAG_MSG_CHAN_MAP_UPDATE = 0x44
TAG_MSG_LOG = 0x50
TAG_MSG_TERMINATE = 0x45
TAG_CMD_RESET = 0x80
TAG_CMD_GET_VERSION = 0x81
TAG_CMD_SNIFF_CHANNEL = 0x82
ADVERTISING_RADIO_ACCESS_ADDRESS = 0x8E89BED6
ADVERTISING_CRC_INIT = 0x555555
config_name = 'config.py'
config_template = '''# Raccoon BLE Sniffer Config

# Output format
# pick one of the following logging formats by uncommenting the format line

# PKLG format minimics HCI data to/from a Bluetooth Controller. It can be opened with Wireshark and Apple's PacketLogger
# format  = 'pklg'

# PCAP format uses Bluetooth BLE Trace format defined by libbt/Ubertooth for use with CrackLE. It can be opened with Wireshark
# format = 'crackle'

# PCAP format uses Bluetooth BLE Trace format defined by Nordic. It can be opened with Wireshark.
format = 'pcap'


# Available Sniffer devices
# List of detected serial ports, please uncomment your Raccoon BLE Sniffer devices
sniffers = [ SNIFFERS ]
mesh = MESHS 

'''
ports = ""
meshs = ""

# vid/pid/baud/rtscts
sniffer_uart_config = [{0x1366, 0x1015, 1000000, 1}]


def as_hex(data):
    str_list = []
    for byte in data:
        str_list.append("{0:02x} ".format(byte))
    return ''.join(str_list)


def addr_str(addr):
    return ':'.join([('%02x' % a) for a in addr[::-1]])


def adv_parser(adv_data):
    while len(adv_data):
        if len(adv_data) < 2:
            return
        item_len = adv_data[0]
        item_type = adv_data[1]
        if len(adv_data) < 1 + item_len:
            return
        item_data = adv_data[2:1 + item_len]
        yield (item_type, item_data)
        adv_data = adv_data[1 + item_len:]


def adv_info_for_data(adv_data):
    info = []
    for (item_type, item_data) in adv_parser(adv_data):
        if item_type == 8 or item_type == 9:
            info.append("%s" % item_data.decode('utf-8'))
    return ', '.join(info)


def create_config_template(config_path):
    global meshs
    global ports
    # get connected devices
    for (device, name, some_id) in comports():
        if 'OpenThread' in name:
            meshs += "{'port':'%s', 'baud': 115200} # %s - %s}\n" % (device, name, some_id)
        if 'raccoon' in name:
            ports += "{ 'port':'%s', 'baud':1000000, 'rtscts':1 },  # %s - %s}\n" % (device, name, some_id)
    with open(config_path, 'wt') as fout:
        config_templated = config_template.replace("SNIFFERS", ports)
        config_templated = config_templated.replace("MESHS", meshs)
        fout.write(config_templated)
    ports = ""
    meshs = ""


"""
User Interface
"""


class ConsoleUI(object):
    def __init__(self):
        self.packets = 0
        self.status_shown = True
        self.connection_event = 0
        self.udp_data = {}
        self.mesh = None

    def process_advertisement(self, packet, rssi, channel):
        # get header
        (adv_header, payload_len) = unpack_from('BB', packet)
        pdu_type = adv_header & 0x0f

        # decode pdu type
        adv_type = ["ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", None, "SCAN_RSP", None, "ADV_SCAN_IND", None, None,
                    None, None, None, None, None, None, None][pdu_type]
        if adv_type is None:
            return

        # get payload
        payload = packet[2:]

        # get addr (as big endian) and adv_data
        addr = addr_str(payload[0:6])
        adv_data = payload[6:]

        # adv data <= 31
        if len(adv_data) > 31:
            return

        # use addr+type
        addr_and_type = "%s||%20s" % (addr, adv_type)

        adv_info = adv_info_for_data(adv_data)

        rssi = -rssi
        if 'GZ' in adv_info:
            # print(addr_and_type + "||%d||" % rssi + adv_info)

            # >>>>>>> mesh >>>>>>>
            if addr not in self.udp_data:
                self.udp_data[addr] = {'mac': addr, 'rssi': [rssi], 'channel': channel}
            else:
                self.udp_data[addr]['rssi'].append(rssi)
            # >>>>>>>>>>>>>>>>>>>>
        if 'RTLS' in adv_info:
            # print(addr_and_type + "||%d||" % rssi + adv_info)

            # >>>>>>> mesh >>>>>>>
            if addr not in self.udp_data:
                self.udp_data[addr] = {'mac': addr, 'rssi': [rssi], 'channel': channel}
            else:
                self.udp_data[addr]['rssi'].append(rssi)
            # >>>>>>>>>>>>>>>>>>>>
        # print(addr_and_type + "||%8d||" % rssi + adv_info)

    def process_packet(self, tag, data):
        if tag == TAG_DATA:
            # parse header
            timestamp_sniffer_us, channel, flags, rssi, aa = unpack_from("<IBBBxI", data)
            # ignore packets with CRC errors for now
            if flags & 4 == 0:
                return
            packet = data[12:-3]
            if aa == 0x8E89BED6:
                self.process_advertisement(packet, rssi, channel)  ########
            else:
                if len(packet) > 2:
                    self.packets += 1
                # print("Connection event %5u, data packets: %u" % (self.connection_event, self.packets))
                return

    # >>>>>>> mesh >>>>>>>
    def send_packet(self):
        udp_dict = self.udp_data.copy()
        self.udp_data.clear()
        if udp_dict:
            for _, data in udp_dict.items():
                udp_data = {'pol': pol_num, 'data': data}
                udp_json = json.dumps(udp_data)
                # print(len(udp_json))
                payload = {'work_code': 7726, 'hole': hole, 'cc_name': cc_name, 'data': udp_json}
                threading.Thread(target=self.server_request, args=payload).start()
            print('-> send mesh network at: ', time.strftime('%c', time.localtime(time.time())))
            # os.system('clear')
        threading.Timer(mesh_interval, self.send_packet).start()

    # >>>>>>>>>>>>>>>>>>>>

    def send_to_server(self):
        while True:
            if self.mesh.readable():
                res = self.mesh.readline()
                res = res.decode()[:len(res) - 1]
                payload = {'work_code': 7726, 'hole': hole, 'cc_name': cc_name, 'data': res}
                threading.Thread(target=self.server_request, args=payload).start()

    def server_request(self, payload):
        requests.get(f'${server_addr}/gz_smartfield/scan_trackingball', params=payload)


"""
Sniffer connection
"""


class Sniffer(object):
    aborted = False
    next_event = None

    def __init__(self, timebase_sec, port, baud, rtscts):
        (self.port, self.baud, self.rtscts) = port, baud, rtscts

        # open serial port, use 0.1 timeout for sync
        self.ser = serial.Serial(self.port, self.baud, timeout=None, rtscts=self.rtscts)

        # with Nordic devkits, UART is only activated after setting DTR
        self.ser.dtr = True

        # try to sync with sniffer
        tries = 0

        # reset sniffer
        self.write(pack('<BH', TAG_CMD_RESET, 0))
        time.sleep(.250)
        while self.ser.in_waiting:
            # reset input buffer
            self.ser.reset_input_buffer()

        # track start offset
        self.start_offset_us = int((time.time() - timebase_sec) * 1000000)

    def write(self, packet):
        self.ser.write(packet)

    def read_packet(self):
        data = self.ser.read(3)
        if self.aborted:
            return None
        if len(data) < 3:
            while (1):
                print("data len %u" % len(data))
        tag, length = unpack("<BH", data)
        data = self.ser.read(length)
        if self.aborted:
            return None
        return (tag, data)

    def read_until_abort(self, queue):
        while not self.aborted:
            event = self.read_packet()
            if event != None:
                (tag, data) = event
                queue.put((time.time(), self.start_offset_us, tag, data))

    def start_reader_thread(self):
        # create event queue
        self.queue = queue.Queue()
        threading.Thread(target=self.read_until_abort, args=[self.queue]).start()

    def peek_event(self):
        if self.next_event == None:
            if self.queue.empty():
                return None
            self.next_event = self.queue.get()
        return self.next_event

    def get_event(self):
        if self.next_event == None:
            self.next_event = self.queue.get()
        event = self.next_event
        self.next_event = None
        return event

    def abort(self):
        self.aborted = True
        self.ser.cancel_read()


"""
Main application
"""


def signal_handler(sig, frame):
    global cfg
    global ui
    print('\nThanks for using raccoon.')
    for sniffer in sniffers:
        sniffer.abort()
    sys.exit(0)


channel_stamp = 37
looper = True

ui = ConsoleUI()
filter_mac = bytearray(6)

# get path to config file
script_path = "/home/pi/Documents/raccoon-master/pyclient"
config_path = config_name
create_config_template(script_path + '/' + config_path)

# load config
sys.path.insert(0, script_path)

import config as cfg

# open log writer
cfg.format = cfg.format.lower()
if cfg.format == 'pcap':
    filename = 'trace.pcap'
    output = PcapNordicTapWriter(filename)
else:
    print('Unknown logging format %s' % cfg.format)
    sys.exit(10)

# >>>>>>> mesh >>>>>>>
mesh_config = cfg.mesh

mesh = serial.Serial(mesh_config['port'], mesh_config['baud'])
ui.mesh = mesh
ui.send_packet()
ui.send_to_server()
# >>>>>>>>>>>>>>>>>>>>

# configuration options
format = 'pcap'
rtscts = 1
log_delay = 0.1
rssi_min = -110

while looper:

    cfg_summary = "Config: output %s (%s), min rssi %d dBm" % (filename, cfg.format, rssi_min)
    print(cfg_summary)

    signal.signal(signal.SIGINT, signal_handler)
    event_cnt = 0
    log_start_sec = int(time.time())
    sniffer_id = 0
    sniffers = []
    for sniffer in cfg.sniffers:
        # get config
        port = sniffer['port']
        baud = sniffer['baud']
        rtscts = sniffer['rtscts']
        channel = channel_stamp

        try:
            # create sniffer and start reading
            sniffer = Sniffer(log_start_sec, port, baud, rtscts)
            sniffer.start_reader_thread()

            # could be part of constructor call
            sniffer.channel = channel

            # check version
            sniffer.write(pack('<BH', TAG_CMD_GET_VERSION, 0))
            (arrival_time, start_offset_us, tag, data) = sniffer.get_event()
            version = ''
            if tag == TAG_CMD_GET_VERSION:
                version = data.decode("utf-8")

            # sniffer info
            print("Sniffer #%x: port %s, baud %u, rtscts %u, channel %u, version %s" % (
                sniffer_id, port, baud, rtscts, channel, version))

            # start listening
            if channel < 40:
                rssi_min_neg = - rssi_min
                sniffer.write(
                    pack('<BHIBII6sB', TAG_CMD_SNIFF_CHANNEL, 20, 0, channel, ADVERTISING_RADIO_ACCESS_ADDRESS,
                         ADVERTISING_CRC_INIT, filter_mac, rssi_min_neg))
            sniffers.append(sniffer)

        except (serial.SerialException, FileNotFoundError):
            print("Failed to connect to sniffer at port %s with %u baud" % (port, baud))

    if len(sniffers) == 0:
        print("No working sniffer found. Please connect sniffer and/or update config.py")
        sys.exit(0)

    last_timestamp_us = 0
    direction_count = [0, 0, 0]

    # process input
    keep = 0
    while keep < channel_interval:

        # log earliest event that has been received at least log_delay seconds ago
        earliest_event_sniffer = None
        earliest_event_timestamp_us = None
        earliest_event_arrival_time = None

        for sniffer in sniffers:
            event = sniffer.peek_event()
            if event == None:
                continue

            # get event time
            (arrival_time, start_offset_us, tag, data) = event
            (timestamp_sniffer_us,) = unpack_from("<I", data)
            timestamp_log_us = start_offset_us + timestamp_sniffer_us

            # store if earlier
            if (earliest_event_timestamp_us == None) or (timestamp_log_us < earliest_event_timestamp_us):
                earliest_event_sniffer = sniffer
                earliest_event_timestamp_us = timestamp_log_us
                earliest_event_arrival_time = arrival_time

        # check if log_delay old
        if (earliest_event_timestamp_us == None) or ((time.time() - earliest_event_arrival_time) < log_delay):
            time.sleep(0.1)
            continue

        # finally, log event
        (arrival_time, start_offset_us, tag, data) = earliest_event_sniffer.get_event()
        timestamp_log_us = earliest_event_timestamp_us
        length = len(data)

        if tag == TAG_MSG_TERMINATE:
            print('\nreset raccoon.')
            for sniffer in sniffers:
                sniffer.abort()
            break
        if tag == TAG_DATA:
            # parse header
            timestamp_sniffer_us, channel, flags, rssi_negative, aa = unpack_from("<IBBBxI", data)
            packet = data[8:]

        # forward packets to ui, too
        ui.process_packet(tag, data)
        keep += 1

    if keep == channel_interval:
        keep = 0
        channel_stamp += 1
        if channel_stamp == 40:
            channel_stamp = 37
        print("channel_changed: ", channel_stamp)
        print('\nreset raccoon.')
        for sniffer in sniffers:
            sniffer.abort()
