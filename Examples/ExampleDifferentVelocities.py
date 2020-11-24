from Gantry import Gantry

'''
    Program to run a protocol using the Gantry library with a three axis X, Y, and Z axis gantry.

    Additional axes can be added easily by adding addition IP address when initializing
'''

x_CMMO_ip_address = "172.21.48.20"  # ip address of the CMMO controlling the x axis
y_CMMO_ip_address = "172.21.48.22"  # ip address of the CMMO controlling the y axis
z_CMMO_ip_address = "172.21.48.24"  # ip address of the CMMO controlling the z axis

all_axes = [x_CMMO_ip_address, y_CMMO_ip_address, z_CMMO_ip_address]

gantry = Gantry(all_axes)  # Gantry(list of CMMO ip addresses)
gantry.enable()  # Turn on the motors. Must enable the gantry in order to move or home.
gantry.home()  # Homes all axis of the gantry

gantry.setVelocities([116, 92, 160])  # set the velocity of each motor in mm/sec. See your motors data sheet or use FCT
                                      # to determine each motors max and min velocity

gantry.moveTo([250, 10, 0])  # move the x y axis over
gantry.moveTo([250, 10, 20])  # move the z axis down
gantry.moveTo([250, 10, 0])  # move the z axis up

gantry.moveTo([250, 170, 0])  # move the y axis over
gantry.moveTo([150, 170, 0], velocities=[30])  # Set the x axis velocity to 30 mm/sec and move the x axis over
gantry.moveTo([50, 160, 20], velocities=[96, 10, 20])   # Set the x y z axis velocities and move to the given coordinate

gantry.setVelocity(1, 92)  # set the velocity of the y axis to 96

gantry.moveTo([50, 10, 0])  # move the y axis over and z axis up

gantry.home()  # home gantry at the end
