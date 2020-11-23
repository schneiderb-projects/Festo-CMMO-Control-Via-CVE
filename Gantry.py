from CMMO import CMMO

'''
    Gantry.py is the top level interface for controlling many CMMO's.
   
    This library is a simple API for control multiple horizontal and vertical axes. 
    
    
'''

class Gantry:
    def __init__(self, horizontal_ip_addresses, vertical_ip_addresses):
        """
        Initialize Gantry

        :param horizontal_ip_addresses: List of IP Address of the CMMO's controlling the horizontal axis, use an empty list if no horizontal axes are used
        :param vertical_ip_addresses: List of IP Address of the CMMO's controlling the vertical axis, use an empty list if no vertical axes are used
        """
        self.listOfCMMOHorizontal = []
        for ip in horizontal_ip_addresses:
            self.listOfCMMOHorizontal.append(CMMO(ip))

        self.listOfCMMOVertical = []
        for ip in vertical_ip_addresses:
            self.listOfCMMOVertical.append(CMMO(ip))

    def enable(self, verbose=False, veryVerbose=False):
        """
        Enable all of the motors for movement. Must call before moving or homing motors.

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for cmmo in self.listOfCMMOVertical:
            s = cmmo.enableControl(verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + cmmo.ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))
            print("CMMO at", cmmo.ip_address, "enabled")

        for cmmo in self.listOfCMMOHorizontal:
            s = cmmo.enableControl(verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + cmmo.ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))
            print("CMMO at", cmmo.ip_address, "enabled")

        self.setPositionMode()

    def home(self, verbose=False, veryVerbose=False):
        """
        Home all motors.

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for cmmo in self.listOfCMMOVertical:
            s = cmmo.home(verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + cmmo.ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))

        for cmmo in self.listOfCMMOHorizontal:
            s = cmmo.home(verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + cmmo.ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))

        self.setPositionMode(verbose=verbose, veryVerbose=veryVerbose)


    def setPositionMode(self, verbose=False, veryVerbose=False):
        """
        Sets the motors into positioning mode in order to receive coordinates. Automatically called after enabling or homing.

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for cmmo in self.listOfCMMOHorizontal:
            cmmo.setPositioningMode(verbose=verbose, veryVerbose=veryVerbose)

        for cmmo in self.listOfCMMOVertical:
            cmmo.setPositioningMode(verbose=verbose, veryVerbose=veryVerbose)

    def moveTo(self, horizontal_locations, vertical_locations,verbose=False, veryVerbose=False ):
        """
        Moves the motors to given coordinates. Vertical motors will always move first.

        :param horizontal_locations: list of locations corresponding to the given list of horizontal axes.
        :param vertical_locations: list of locations corresponding to the given list of vertical axes.
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for i, l in enumerate(vertical_locations):
            if l == -1:
                continue
            s = self.listOfCMMOVertical[i].moveTo(l, verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + self.vertical_locations[i].ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))

        for i, l in enumerate(horizontal_locations):
            if l == -1:
                continue
            s = self.listOfCMMOHorizontal[i].moveTo(l, verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + self.horizontal_locations[i].ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))

    def disconnect(self):
        """
        disconnect from all CMMOs
        """
        for cmmo in self.listOfCMMOVertical:
            cmmo.finish()

        for cmmo in self.listOfCMMOHorizontal:
            cmmo.finish()