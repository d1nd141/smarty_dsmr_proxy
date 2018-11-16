import serial
import binascii
import argparse
import paho.mqtt.client as mqtt

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.exceptions import InvalidTag


class SmartyProxy():
    def __init__(self):
        # Constants that describe the individual steps of the state machine:

        # Initial state. Input is ignored until start byte is detected.
        self.STATE_IGNORING = 0
        # Start byte (hex "DB") has been detected.
        self.STATE_STARTED = 1
        # Length of system title has been read.
        self.STATE_HAS_SYSTEM_TITLE_LENGTH = 2
        # System title has been read.
        self.STATE_HAS_SYSTEM_TITLE = 3
        # Additional byte after the system title has been read.
        self.STATE_HAS_SYSTEM_TITLE_SUFFIX = 4
        # Length of remaining data has been read.
        self.STATE_HAS_DATA_LENGTH = 5
        # Additional byte after the remaining data length has been read.
        self.STATE_HAS_SEPARATOR = 6
        # Frame counter has been read.
        self.STATE_HAS_FRAME_COUNTER = 7
        # Payload has been read.
        self.STATE_HAS_PAYLOAD = 8
        # GCM tag has been read.
        self.STATE_HAS_GCM_TAG = 9
        # All input has been read. After this, we switch back to STATE_IGNORING and wait for a new start byte.
        self.STATE_DONE = 10

        self.mqtt_topic = "TOPIC"
        self.mqtt_host = "MQTT_SERVER"
        self.mqtt_port = 1883
        self.mqtt_username = "USERNAME"
        self.mqtt_password = "PASSWORD"

        # Command line arguments
        self._args = {}

        # Serial connection from which we read the data from the smart meter
        self._connection = None

        # Initial empty values. These will be filled as content is read
        # and they will be reset each time we go back to the initial state.
        self._state = self.STATE_IGNORING
        self._buffer = ""
        self._buffer_length = 0
        self._next_state = 0
        self._system_title_length = 0
        self._system_title = b""
        self._data_length_bytes = b""  # length of "remaining data" in bytes
        self._data_length = 0  # length of "remaining data" as an integer
        self._frame_counter = b""
        self._payload = b""
        self._gcm_tag = b""
        self.client = mqtt.Client(client_id="smarty",clean_session=False)

    # The callback for when the client receives a CONNACK response from the server.
    def on_connect(client, userdata, flags, rc):
        print("Connected with result code "+str(rc))

        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        client.subscribe("$SYS/#")

    # The callback for when a PUBLISH message is received from the server.
    def on_message(client, userdata, msg):
        print(msg.topic+" "+str(msg.payload))


    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('key', help="Decryption key")
        parser.add_argument('-i', '--serial-input-port', required=False, default="/dev/ttyUSB0", help="Input port. Defaults to /dev/ttyUSB0.")
        parser.add_argument('-o', '--serial-output-port', required=False, help="Output port, e.g. /dev/pts/2.")
        self._args = parser.parse_args()
#        client.on_connect = on_connect
#        client.on_message = on_message
        self.client.username_pw_set(self.mqtt_username, password=self.mqtt_password)
        self.client.connect(self.mqtt_host, self.mqtt_port, 60)
        self.client.publish(self.mqtt_topic, "startup")


        self.connect()
        while True:
            self.process()

    # Connect to the serial port when we run the script
    def connect(self):
        try:
            self._connection = serial.Serial(
                port=self._args.serial_input_port,
                baudrate=115200,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )
        except (serial.SerialException, OSError) as err:
            print("ERROR")

    # Start processing incoming data
    def process(self):
        try:
            raw_data = self._connection.read()
        except serial.SerialException:
            return

        # Read and parse the stream from the serial port byte by byte.
        # This parsing works as a state machine (see the definitions in the __init__ method).
        # See also the official documentation on http://smarty.creos.net/wp-content/uploads/P1PortSpecification.pdf
        # For better human readability, we use the hexadecimal representation of the input.
        hex_input = binascii.hexlify(raw_data)

        # Initial state. Input is ignored until start byte is detected.
        if self._state == self.STATE_IGNORING:
            if hex_input == b'db':
                self._state = self.STATE_STARTED
                self._buffer = b""
                self._buffer_length = 1
                self._system_title_length = 0
                self._system_title = b""
                self._data_length = 0
                self._data_length_bytes = b""
                self._frame_counter = b""
                self._payload = b""
                self._gcm_tag = b""
            else:
                return

        # Start byte (hex "DB") has been detected.
        elif self._state == self.STATE_STARTED:
            self._state = self.STATE_HAS_SYSTEM_TITLE_LENGTH
            self._system_title_length = int(hex_input, 16)
            self._buffer_length = self._buffer_length + 1
            self._next_state = 2 + self._system_title_length  # start bytes + system title length

        # Length of system title has been read.
        elif self._state == self.STATE_HAS_SYSTEM_TITLE_LENGTH:
            if self._buffer_length > self._next_state:
                self._system_title += hex_input
                self._state = self.STATE_HAS_SYSTEM_TITLE
                self._next_state = self._next_state + 2  # read two more bytes
            else:
                self._system_title += hex_input

        # System title has been read.
        elif self._state == self.STATE_HAS_SYSTEM_TITLE:
            self._next_state = self._next_state + 1
            self._state = self.STATE_HAS_SYSTEM_TITLE_SUFFIX  # Ignore separator byte

        # Additional byte after the system title has been read.
        elif self._state == self.STATE_HAS_SYSTEM_TITLE_SUFFIX:
            if self._buffer_length > self._next_state:
                self._data_length_bytes += hex_input
                self._data_length = int(self._data_length_bytes, 16)
                self._state = self.STATE_HAS_DATA_LENGTH
            else:
                self._data_length_bytes += hex_input

        # Length of remaining data has been read.
        elif self._state == self.STATE_HAS_DATA_LENGTH:
            self._state = self.STATE_HAS_SEPARATOR  # Ignore separator byte
            self._next_state = self._next_state + 1 + 4  # separator byte + 4 bytes for framecounter

        # Additional byte after the remaining data length has been read.
        elif self._state == self.STATE_HAS_SEPARATOR:
            if self._buffer_length > self._next_state:
                self._frame_counter += hex_input
                print("Framecounter")
                print(self._frame_counter)
                self._state = self.STATE_HAS_FRAME_COUNTER
                self._next_state = self._next_state + self._data_length - 17
            else:
                self._frame_counter += hex_input

        # Frame counter has been read.
        elif self._state == self.STATE_HAS_FRAME_COUNTER:
            if self._buffer_length > self._next_state:
                self._payload += hex_input
                self._state = self.STATE_HAS_PAYLOAD
                self._next_state = self._next_state + 12
            else:
                self._payload += hex_input

        # Payload has been read.
        elif self._state == self.STATE_HAS_PAYLOAD:
            # All input has been read. After this, we switch back to STATE_IGNORING and wait for a new start byte.
            if self._buffer_length > self._next_state:
                self._gcm_tag += hex_input
                self._state = self.STATE_DONE
            else:
                self._gcm_tag += hex_input

        self._buffer += hex_input
        self._buffer_length = self._buffer_length + 1

        if self._state == self.STATE_DONE:
            # print(self._buffer)
            self.analyze()
            self._state = self.STATE_IGNORING

    # Once we have a full encrypted "telegram", put everything together for decryption.
    def analyze(self):
        key = binascii.unhexlify(self._args.key)
        additional_data = binascii.unhexlify("3000112233445566778899AABBCCDDEEFF")
        iv = binascii.unhexlify(self._system_title + self._frame_counter)
        payload = binascii.unhexlify(self._payload)
        gcm_tag = binascii.unhexlify(self._gcm_tag)

        try:
            decryption = self.decrypt(
                key,
                additional_data,
                iv,
                payload,
                gcm_tag
            )
            print(decryption)
            tempstring=decryption.decode()
            temparray = tempstring.split("\r\n\r\n")
            i=0
            for item in temparray:
                if i > 0:
                    temparray2=item.split("\r\n")
                    for item2 in temparray2:
                        if item2.rfind(":") > 0:
                            item2=item2.split(":")[1]
                            name=item2.split("(")[0]
                            value=item2.split("(")[1]
                            value=value.replace("(","")
                            value=value.replace(")","")
                            if value.rfind("*") > 0:
                                value=value.split("*")[0]
                            if len(value) > 0:
                                self.write_to_mqtt(name,value)
                i+=1
            if self._args.serial_output_port:
                self.write_to_serial_port(decryption)
        except InvalidTag:
            print("ERROR: Invalid Tag.")

    # Do the actual decryption (AES-GCM)
    def decrypt(self, key, additional_data, iv, payload, gcm_tag):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, gcm_tag, 12),
            backend=default_backend()
        ).decryptor()

        decryptor.authenticate_additional_data(additional_data)

        return decryptor.update(payload) + decryptor.finalize()

    # Write the decrypted data to a serial port (e.g. one created with socat)
    def write_to_serial_port(self, decryption):
        ser = serial.Serial(
            port=self._args.serial_output_port,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
        )
        ser.write(decryption)
        ser.close()

    def write_to_mqtt(self, topic, decryption):
        self.client.publish(topic=self.mqtt_topic+topic, payload=decryption,retain=True)

if __name__ == '__main__':
    smarty_proxy = SmartyProxy()
    smarty_proxy.main()
