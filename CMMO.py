from time import sleep
from CVE import CVE, formatBin

class CMMO:
    def __init__(self, ip_address, useDefaultConversion=True, conversionMillimeters=1):
        """
        initialize CMMO and open TCP connection
        :param ip_address: address of the CMMO
        :param useDefaultConversion: use the default conversion ratio of 1000:1 for mm:CMMO units (SINC)
        :param conversionMillimeters: if not using default conversion ratio, give the number of millimeters in record #1
        """
        self.ip_address = ip_address
        self.cve = CVE(ip_address)
        self.setCVEMode()
        if useDefaultConversion:
            self.conversionRatio = 1000
        else:
            self.conversionRatio = int(self.getConversion(millimeters=conversionMillimeters))

    def setCVEMode(self, verbose=False, veryVerbose=False):
        """
        set the CMMO to CVE mode

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :return: Dictionary containing important transmission information. See method CVE.parseWriteResponse(r) for more details.
        """
        p = self.cve.send_receive_write('UINT08', 3, 0, 0x02, verbose=veryVerbose)
        if verbose:
            print("ACK:", p["ACK message"])
            print()
        return p

    def home(self, verbose=False, veryVerbose=False, sleepTime=.1):
        """
        Home the CMMOs motor

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        p = self.cve.send_receive_write('SINT08', 120, 0, 6, verbose=veryVerbose)
        if verbose:
            print("ACK:", p["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        s = self.cve.send_receive_read(121, 0, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        self.cve.writeControl(0x0000001F)
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        while s["payload bytes"][-2:] != b'\xC4\x27':
            self.cve.writeControl(0x0000001F)
            sleep(sleepTime)
            s = self.cve.readStatus(verbose=veryVerbose)
            if verbose:
                print("ACK:", s["ACK message"])
                print("Payload HEX:", s["payload hex"])
                print("Payload BIN:", formatBin(s["payload bin"]))
                print()

        self.cve.writeControl(0x0000000F)
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def enableControl(self, verbose=False, veryVerbose=False, sleepTime=.1):
        """
        enable control of the CMMOs motor

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        s = self.cve.send_receive_write('UINT08', 3, 0, 0x02, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        s = self.cve.writeControl(0x00000006)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        s = self.cve.writeControl(0x00000007)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        s = self.cve.writeControl(0x0000000F)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def getConversion(self, verbose=False, veryVerbose=False, record=1, millimeters=1):
        """
        get conversion ratio of mm:SINC

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param record: which record is being used to determine the ratio
        :param millimeters: position in millimeters written to the record
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_read(6, record, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s["payload"] / millimeters

    def setPositioningMode(self, sleepTime=.1, verbose=False, veryVerbose=False):
        """
        set the CMMO to positioning mode

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_write('SINT08', 120, 0, 1, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print()

        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()
        s = self.cve.send_receive_read(121, 0, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()
        return s

    def setRecord(self, record=1, verbose=False, veryVerbose=False):
        """
        set the current record to be run

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :return: Dictionary containing important transmission information from reading current record object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_write('UINT08', 31, 0, record, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print()


        s = self.cve.send_receive_read(141, 0, verbose=veryVerbose)
        s2 = self.cve.send_receive_read(60, 0, verbose=veryVerbose)

        if verbose:
            print("Record Number:", s["payload"])
            print("Target Position:", s2["payload"])

        return s

    def runRecord(self, sleepTime=.1, verbose=False, veryVerbose=False):
        """
        run a record

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.writeControl(0x0000000F)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        s = self.cve.writeControl(0x0000001F)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        sleep(sleepTime)
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        while s["payload bytes"][-2:] != b'\xC4\x27':
            self.cve.writeControl(0x0000001F)
            sleep(sleepTime)
            s = self.cve.readStatus(verbose=veryVerbose)
            if verbose:
                print("ACK:", s["ACK message"])
                print("Payload HEX:", s["payload hex"])
                print("Payload BIN:", formatBin(s["payload bin"]))
                print()

        s = self.cve.writeControl(0x0000000F)

        return s

    def setTargetLocation(self, millimeters, record=1, verbose=False, veryVerbose=False):
        """
        set the target location of a record

        :param millimeters: target location in millimeters (gets converted to SINC before sending)
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :param record: record number to set the location of
        :return: Dictionary containing important transmission information from reading the status object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_write('SINT32', 6, record, millimeters * self.conversionRatio, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print()
        s = self.cve.readStatus(verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def getTargetPosition(self, verbose=False, veryVerbose=False):
        """
        get the current target position

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :return: Dictionary containing important transmission information from reading the current target position object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_read(60, 0, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def getTargetPosition2(self, verbose=False, veryVerbose=False):
        """
        also gets the target position, but from reading a different object

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :return: Dictionary containing important transmission information from reading the current target position object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_read(295, 0, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def getCurrentRecord(self, verbose=False, veryVerbose=False):
        """
        get the number of the current record being run

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :return: Dictionary containing important transmission information from reading the current target position object. See method CVE.parseReadResponse(r) for more details.
        """
        s = self.cve.send_receive_read(141, 0, verbose=veryVerbose)
        if verbose:
            print("ACK:", s["ACK message"])
            print("Payload HEX:", s["payload hex"])
            print("Payload BIN:", formatBin(s["payload bin"]))
            print()

        return s

    def moveTo(self, millimeters, record=1, sleepTime=.1, verbose=False, veryVerbose=False):
        """
        move to a given location in mm

        :param millimeters: target location in millimeters (gets converted to SINC before sending)
        :param sleepTime: wait time before requesting status object to check if the motion is finished
        :param record: record number to set the location of and run
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        :return: Dictionary containing important transmission information from reading the current target position object. See method CVE.parseReadResponse(r) for more details.
        """
        self.setRecord(record=record, verbose=verbose, veryVerbose=veryVerbose)
        self.setTargetLocation(millimeters, record=1, verbose=verbose, veryVerbose=veryVerbose)
        s = self.runRecord(sleepTime=sleepTime, verbose=verbose, veryVerbose=veryVerbose)
        return s

    def finish(self):
        """
        close connection
        """
        self.cve.close()