import threading
from multiprocessing.dummy import Pool as ThreadPool

from CMMO import CMMO

'''
    Gantry.py is the top level interface for controlling many CMMO's.
   
    This library is a simple API for controlling axes. 
'''

class Gantry:
    def __init__(self, CMMO_ip_addresses):
        """
        Initialize Gantry

        :param CMMO_ip_addresses: List of IP Address of the CMMO's
        """
        self.allMotors = []
        for ip in CMMO_ip_addresses:
            self.allMotors.append(CMMO(ip))

    def enable(self, verbose=False, veryVerbose=False):
        """
        Enable all of the motors for movement. Must call before moving or homing motors.

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """

        for cmmo in self.allMotors:
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

        def home_thread(cmmo):
            s = cmmo.home(verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + cmmo.ip_address + ": ERROR MESSAGE = " + str(s["ACK message"]))

        if len(self.allMotors) > 0:
            pool = ThreadPool(len(self.allMotors))
            pool.map(home_thread, self.allMotors)

            pool.close()
            pool.join()

        self.setPositionMode(verbose=verbose, veryVerbose=veryVerbose)

    def setPositionMode(self, verbose=False, veryVerbose=False):
        """
        Sets the motors into positioning mode in order to receive coordinates. Automatically called after enabling or homing.

        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for cmmo in self.allMotors:
            cmmo.setPositioningMode(verbose=verbose, veryVerbose=veryVerbose)

    def moveTo(self, locations, velocities=None, verbose=False, veryVerbose=False):
        """
        Moves the motors to given coordinates.

        :param locations: list of locations corresponding to the given list of motors.
        :param velocities: list of desired motor velocities in mm/sec
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """

        if velocities is not None:
            self.setVelocities(velocities, verbose=verbose, veryVerbose=veryVerbose)

        def move_thread(arg):
            cmmo = arg[0]
            l = arg[1]
            if l == -1:
                return
            s = cmmo.moveTo(l, verbose=verbose, veryVerbose=veryVerbose)
            if s["ACK message"] != "Everything Ok":
                raise RuntimeError("Failed to Enable Control of Device at IP Address "
                                   + self.vertical_locations[i].ip_address + ": ERROR MESSAGE = " + str(
                    s["ACK message"]))

        if len(self.allMotors) > 0 and len(locations) > 0:
            megaArray = []
            for m, l in zip(self.allMotors, locations):
                megaArray.append([m, l])
            pool = ThreadPool(len(megaArray))
            pool.map(move_thread, megaArray)

            pool.close()
            pool.join()

    def setVelocity(self, index, velocity, verbose=False, veryVerbose=False):
        """
        Set the velocity of a motor at the given index in mm/sec. The index refers to the order in which the CMMO IP addresses were given.

        :param index: Index of the motor
        :param velocity: Desired velocity in mm/sec
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """

        if velocity == 0:
            return

        self.allMotors[index].setVelocity(velocity, verbose=verbose, veryVerbose=veryVerbose)

    def setVelocities(self, velocities, verbose=False, veryVerbose=False):
        """
        Set the velocities of the motors to the given velocities.

        :param velocities: Desired velocities in mm/sec
        :param verbose: print high level debugging information to the console
        :param veryVerbose: print low level debugging information to the console, useful for understanding CVE
        """
        for m, v in zip(self.allMotors, velocities):
            if v == 0:
                continue
            m.setVelocity(v, verbose=verbose, veryVerbose=veryVerbose)

    def disconnect(self):
        """
        disconnect from all CMMOs
        """
        for cmmo in self.allMotors:
            cmmo.finish()
