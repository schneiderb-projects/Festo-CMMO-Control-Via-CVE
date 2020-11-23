import socket

def parseReadResponse(r):
    """
    parse bytes of read response message into dictionary
    """
    return {"service": r[0:1],
            "ID": r[1:5],
            "data length": r[5:9],
            "ACK": r[9:10],
            "ACK message": determineAck(r[9:10]),
            "index": r[0x0E:0x10],
            "subindex": r[0x10:0x11],
            "data type": determineType(r[0x11:0x12]),
            "payload": int.from_bytes(r[0x12:0x16], 'little'),
            "payload hex": toHex(r[0x12:0x16][::-1]),
            "payload bytes": r[0x12:0x16][::-1],
            "payload bin": bin(int.from_bytes(r[0x12:0x16], 'little'))}

def parseWriteResponse(r):
    """
    parse bytes of write response message into dictionary
    """

    return {"service": r[0:1],
            "ID": r[1:5],
            "data length": r[5:9],
            "ACK": r[9:10],
            "ACK message": determineAck(r[9:10]),
            "index": r[0x0E:0x10],
            "subindex": r[0x10:0x11],
            "data type": determineType(r[0x11:0x12])}

def toLittleEndianHex(num, desiredBytes):
    """
    convert a number in little endian hex value with the given number of bytes
    """
    h_str = hex(num)[2:]
    h_str = ('0' * (desiredBytes * 2 - len(h_str))) + h_str
    h_bytes = bytes.fromhex(h_str)[::-1]
    return h_bytes


def determineTypeFromName(c):
    """
    convert string name to corresponding type code
    """
    if c == "UINT32":
        return b'\x02'
    if c == "UINT16":
        return b'\x03'
    if c == "UINT08":
        return b'\x04'
    if c == "SINT32":
        return b'\x06'
    if c == "SINT16":
        return b'\x07'
    if c == "SINT08":
        return b'\x08'
    return None


def build_write(dataType, index, subindex, payload, id=0xEFBEADDE):
    """
    build a write message using the given arguments
    """
    service = b'\x11'
    id = toLittleEndianHex(id, 4)
    length = toLittleEndianHex(dataType_Length(dataType) + 4, 4)
    if length is None:
        raise RuntimeError("Invalid Data Type")
    ack = b'\x00'
    placeholder = b'\x00\x00\x00\x00'
    index = toLittleEndianHex(index, 2)
    subindex = hex(subindex)[2:]
    subindex = bytes.fromhex(('0' * (len(subindex) % 2)) + subindex)
    dataTypeName = determineTypeFromName(dataType)
    if dataTypeName is None:
        raise RuntimeError("Invalid Data Type")
    payload = toLittleEndianHex(payload, dataType_Length(dataType))
    return service + id + length + ack + placeholder + index + subindex + dataTypeName + payload


def build_read(index, subindex, id=0xEFBEADDE):
    """
    build a read message from the given arguments
    """
    service = b'\x10'
    id = toLittleEndianHex(id, 4)
    length = toLittleEndianHex(4, 4)
    if length is None:
        raise RuntimeError("Invalid Data Type")
    ack = b'\x00'
    placeholder = b'\x00\x00\x00\x00'
    index = toLittleEndianHex(index, 2)
    subindex = hex(subindex)[2:]
    subindex = bytes.fromhex(('0' * (len(subindex) % 2)) + subindex)
    placeHolder2 = b'\x00'
    return service + id + length + ack + placeholder + index + subindex + placeHolder2


def dataType_Length(type):
    """
    get the byte length of a type from the string name
    """
    if type[-1] == "8":
        return 1
    if type[-2:] == "16":
        return 2
    if type[-2:] == "32":
        return 4
    return None


def formatBin(b, length=32):
    """
    format a binary string to make it more readable
    """
    toReturn = ""
    s = b[:2]
    s2 = b[2:]
    if len(s2) < length:
        s2 = ('0' * (length - len(s2))) + s2

    for i, x in enumerate(reversed(s2)):
        if i != 0 and i % 4 == 0:
            toReturn = " " + toReturn
        toReturn = x + toReturn

    return s + toReturn


def determineService(s):
    """
    convert service code to string
    """
    if s == b'\x10':
        return "Read CVE object from CMMO"
    if s == b'\x11':
        return "Write CVE object to CMMO"
    return "Invalid Service ID"


def determineAck(a):
    """
    convert ACK code to ACK message
    """
    if a == b'\x00':
        return "Everything Ok"
    if a == b'\x01':
        return "Service is not supported: Check the service ID of the request"
    if a == b'\x03':
        return "User data length of the request is invalid: Check the structure of the request"
    if a == b'\xA0':
        return "Range of values of another CVE object violated: Writing the CVE object would cause the range of " \
               "values of another CVE object to be violated"
    if a == b'\xA2':
        return "Invalid object index, Correct the object index"
    if a == b'\xA4':
        return "The CVE object cannot be read"
    if a == b'\xA5':
        return "The CVE object cannot be written"
    if a == b'\xA6':
        return "The CVE object cannot be written while the drive is in an \"Operation enabled\" status: Quit the " \
               "\"Operation enabled\" status"
    if a == b'\xA7':
        return "The CVE object must not be written without master control: Assign master control to the CVE " \
               "interface. Use CVE object #3 for this purpose"
    if a == b'\xA9':
        return "The CVE object cannot be written, as the value is lower than the minimum value: Set to a valid value"
    if a == b'\xAB':
        return "The CVE object cannot be written, as the value is not within the valid value set: Set to a valid value"
    if a == b'\xAC':
        return "The CVE object cannot be written, as the specified data type is incorrect: Set to a valid value"
    if a == b'\xAD':
        return "The CVE object cannot be written, as it is password-protected: Cancel the password protection"
    return "Invalid Ack"


def determineType(c):
    """
    convert type code to type string
    """
    if c == b'\x02':
        return "UINT32"
    if c == b'\x03':
        return "UINT16"
    if c == b'\x04':
        return "UINT08"
    if c == b'\x06':
        return "SINT32"
    if c == b'\x07':
        return "SINT16"
    if c == b'\x08':
        return "SINT08"
    return "Invalid Type"


def toHex(n):
    """
    convert a number to a hex string
    """
    n = n.hex()
    s = "0x"
    s2 = ""
    for i in range(0, len(n), 2):
        s2 += n[i] + n[i+1] + " "
    return s + s2.upper()


def status(b):
    """
    return yes if True and no if False
    """
    if b:
        return "YES"
    return "NO"


def printRequestWrite(r):
    """
    print a write request packet
    """
    print("\nWRITE REQUEST------------------------------------------------------------------------------------------")
    print("Meaning\t\t\t\t\t\t|", "Data Type\t|", "Value\t\t\t\t|", "Info", )
    print()
    print("Service:\t\t\t\t\t|", "UINT08", "\t|", toHex(r[0:1]), "\t\t\t|", determineService(r[0:1]) +
          ", Response Should Match")
    print("ID (Little E):\t\t\t\t|", "UINT32", "\t|", toHex(r[1:5]), "\t|", "Response Should Match")
    print("Data Length (Little E):\t\t|", "UINT32", "\t|", toHex(r[5:9]), "\t|", "Length = len(dataType) + 4")
    print("ACK:\t\t\t\t\t\t|", "UINT08", "\t|", toHex(r[9:10]), "\t\t\t|", "Always 0x00")
    print("Placeholder:\t\t\t\t|", "UINT32", "\t|", toHex(r[0x0A:0x0E]), "\t|",
          "Should be all 0x00")
    print("Object Index (Little E):\t|", "UINT16", "\t|", toHex(r[0x0E:0x10]), "\t\t\t|",
          "Object # Being Read, Response Should Match")
    print("Subindex:\t\t\t\t\t|", "UINT08", "\t|", toHex(r[0x10:0x11]), "\t\t\t|",
          "Record # being Read, Response Should Match")
    print("Data Type:\t\t\t\t\t|", "UINT08", "\t|", toHex(r[0x11:0x12]), "\t\t\t|", "TYPE="
          + determineType(r[0x11:0x12]) + ", Response Should Match")
    print("Object Value (Little E):\t|", determineType(r[0x11:0x12]), "\t|", toHex(r[0x12:0x16]), "\t|",
          "Payload Value, Length Determined by Data Type")
    print("--------------------------------------------------------------------------------------------------------")


def printRequestRead(r):
    """
    print a read request packet
    """
    print("\nREAD REQUEST------------------------------------------------------------------------------------------")
    print("Meaning\t\t\t\t\t\t|", "Data Type\t|", "Value\t\t\t\t|", "Info", )
    print()
    print("Service:\t\t\t\t\t|", "UINT08", "\t|", toHex(r[0:1]), "\t\t\t|", determineService(r[0:1]) +
          ", Response Should Match")
    print("ID (Little E):\t\t\t\t|", "UINT32", "\t|", toHex(r[1:5]), "\t|", "Response Should Match")
    print("Data Length (Little E):\t\t|", "UINT32", "\t|", toHex(r[5:9]), "\t|", "Always 4")
    print("ACK:\t\t\t\t\t\t|", "UINT08", "\t|", toHex(r[9:10]), "\t\t\t|", "Always 0x00")
    print("Placeholder:\t\t\t\t|", "UINT32", "\t|", toHex(r[0x0A:0x0E]), "\t|",
          "Should be all 0x00")
    print("Object Index (Little E):\t|", "UINT16", "\t|", toHex(r[0x0E:0x10]), "\t\t\t|",
          "Object # Being Read, Response Should Match")
    print("Subindex:\t\t\t\t\t|", "UINT08", "\t|", toHex(r[0x10:0x11]), "\t\t\t|",
          "Record # being Read, Response Should Match")
    print("PlaceHolder:\t\t\t\t|", "UINT08", "\t|", toHex(r[0x11:0x12]), "\t\t\t|", "Always 0x00")
    print("--------------------------------------------------------------------------------------------------------")

def printResponseWrite(r, m):
    """
    print a write response packet
    """
    print("\nWRITE RESPONSE------------------------------------------------------------------------------------------")
    print("Meaning\t\t\t\t\t\t|", "Status\t|", "Value\t\t\t\t|", "Info", )
    print()
    print("Service:\t\t\t\t\t|", status(m[0:1] == r[0:1]), "\t\t|", toHex(r[0:1]), "\t\t\t|",
          determineService(r[0:1]) + ", Should match message sent")
    print("ID (Little E):\t\t\t\t|", status(m[1:5] == r[1:5]), "\t\t|", toHex(r[1:5]), "\t|",
          "Should match message sent")
    print("Data Length (Little E):\t\t|", "N/A\t\t|", toHex(r[5:9]), "\t|", "len(data) = 4 bytes + len(data type)")
    print("ACK:\t\t\t\t\t\t|", status(r[9:10] == b'\x00'), "\t\t|", toHex(r[9:10]), "\t\t\t|", determineAck(r[9:10]))
    print("Placeholder:\t\t\t\t|", status(r[0x0A:0x0E] == b'\x00\x00\x00\x00'), "\t\t|", toHex(r[0x0A:0x0E]), "\t|",
          "Should be all 0x00")
    print("Object Index (Little E):\t|", status(m[0x0E:0x10] == r[0x0E:0x10]), "\t\t|", toHex(r[0x0E:0x10]), "\t\t\t|",
          "Should match message sent")
    print("Subindex:\t\t\t\t\t|", status(m[0x10:0x11] == r[0x10:0x11]), "\t\t|", toHex(r[0x10:0x11]), "\t\t\t|",
          "Should match message sent")
    print("Data Type:\t\t\t\t\t|", status(m[0x11:0x12] == r[0x11:0x12]), "\t\t|", toHex(r[0x11:0x12]), "\t\t\t|",
          "TYPE=" + determineType(r[0x11:0x12]) + ", Should match message sent")
    print("--------------------------------------------------------------------------------------------------------")

def printResponseRead(r, m):
    """
    print a read response packet
    """
    print("\nREAD RESPONSE-------------------------------------------------------------------------------------------")
    print("Meaning\t\t\t\t\t\t|", "Status\t|", "Value\t\t\t\t|", "Info", )
    print()
    print("Service:\t\t\t\t\t|", status(m[0:1] == r[0:1]), "\t\t|", toHex(r[0:1]), "\t\t\t|",
          determineService(r[0:1]) + ", Should match message sent")
    print("ID (Little E):\t\t\t\t|", status(m[1:5] == r[1:5]), "\t\t|", toHex(r[1:5]), "\t|", "Should match message "
                                                                                              "sent")
    print("Data Length (Little E):\t\t|", "N/A\t\t|", toHex(r[5:9]), "\t|", "len(data) = 4 bytes + len(data type)")
    print("ACK:\t\t\t\t\t\t|", status(r[9:10] == b'\x00'), "\t\t|", toHex(r[9:10]), "\t\t\t|", determineAck(r[9:10]))
    print("Placeholder:\t\t\t\t|", status(r[0x0A:0x0E] == b'\x00\x00\x00\x00'), "\t\t|", toHex(r[0x0A:0x0E]), "\t|",
          "Should be all 0x00")
    print("Object Index (Little E):\t|", status(m[0x0E:0x10] == r[0x0E:0x10]), "\t\t|", toHex(r[0x0E:0x10]), "\t\t\t|",
          "Should match message sent")
    print("Subindex:\t\t\t\t\t|", status(m[0x10:0x11] == r[0x10:0x11]), "\t\t|", toHex(r[0x10:0x11]), "\t\t\t|",
          "Should match message sent")
    print("Data Type:\t\t\t\t\t|", status(status(determineType(r[0x11:0x12])) != "Invalid Type"), "\t\t|",
          toHex(r[0x11:0x12]), "\t\t\t|", "TYPE=" + determineType(r[0x11:0x12])
          + ", Should match message sent")
    print("Object Value (Little E):\t|", "N/A\t\t|", toHex(r[0x12:0x16]), "\t|", "Payload Value")
    print("--------------------------------------------------------------------------------------------------------")

def send_message(message, s, verbose=False):
    """
    send a tcp message
    :param message: message to send
    :param s: active tcp socket
    :param verbose: print debugging information to console
    :return:
    """
    if isinstance(message, str):
        message = bytes.fromhex(message)
    s.sendall(message)  # encode string
    if verbose:
        print("sent:\t\t", toHex(message))
    return True

def connect(ip, port_number):
    """
    open tcp socket at given IP and Port Number

    :param ip: IP address
    :param port_number:  port number
    :return: active tcp socket
    """
    print("attempting to connect to " + str(ip) + " at port " + str(port_number))
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # build socket
    soc.connect((ip, port_number))  # attempt connection
    print("connected to " + str(ip) + " at port " + str(port_number))
    return soc

def get_message(s, verbose=False):
    """
    get a tcp message
    :param s: open socket to recieve from
    :param verbose: print debuggin information to console
    :return: message received
    """
    r = s.recv(1024)
    if verbose:
        print("received:\t", toHex(r))
    return r


class CVE:
    def __init__(self, ip_address, port=49700):
        """
        Initialize CVE connection

        :param ip_address: ip_address to connect to
        :param port: Port to connect to. Default port is 49700.
        """
        self.sock = None

        while True:  # iterate ports 12000 - 12005
            try:
                self.sock = connect(ip_address, port)  # attempt connection
                break
            except:
                raise RuntimeError("Unable to Connect to CMM0 at ip_address " + str(ip_address))
                exit(3)

    def send_receive_write(self, dataType, index, subindex, payload, id=0xEFBEADDE, verbose=False) -> dict:
        """
        Send a message  of the specified data type to the object at the specified index and subindex, with the specified
        payload

        :param dataType: A string with the name of the data type (UINT08, UINT16, UINT32, SINT08, SINT16, SINT32). Data type must match the target object.
        :param index: index of the target object
        :param subindex: subindex of the target object. Usually 0.
        :param payload: value to send
        :param id: ID of the message. This value has no effect on the actual message.
        :param verbose: Print debug info to console
        :return: Dictionary containing important transmission information. See method parseWriteResponse(r) for more details.
        """
        if verbose:
            print("\n====================================================================================================="
                  "=================")
        message = build_write(dataType, index, subindex, payload, id=id)
        send_message(message, self.sock, verbose=verbose)
        r = get_message(self.sock, verbose=verbose)
        p = parseWriteResponse(r)
        if verbose:
            printRequestWrite(message)
            printResponseWrite(r, message)
            print("======================================================================================================="
                  "===============")

        return p

    def send_receive_read(self, index, subindex, id=0xEFBEADDE, verbose=False) -> dict:
        """
        Send a message  of the specified data type to the object at the specified index and subindex, with the specified
        payload

        :param index: index of the target object
        :param subindex: subindex of the target object. Usually 0.
        :param id: ID of the message. This value has no effect on the actual message.
        :param verbose: Print debug info to console
        :return: Dictionary containing important transmission information. See method parseReadResponse(r) for more details.
        """
        if verbose:
            print("\n====================================================================================================="
                  "=================")
        message = build_read(index, subindex, id=id)
        send_message(message, self.sock, verbose=verbose)
        r = get_message(self.sock, verbose=verbose)
        p = parseReadResponse(r)
        if verbose:
            printRequestRead(message)
            printResponseRead(r, message)
            print("======================================================================================================"
                  "================")

        return p

    def readStatus(self, verbose=True) -> dict:
        """
        read the status object of the CMMO

        :param verbose: Print debugging information to the console
        :return: Dictionary containing important transmission information. See method parseReadResponse(r) for more details.
        """
        return self.send_receive_read(1, 0, verbose=verbose)

    def writeControl(self, word, verbose=False) -> dict:
        return self.send_receive_write('UINT32', 2, 0, word, verbose=verbose)


    def close(self):
        """
        close the connection
        """
        self.sock.close()