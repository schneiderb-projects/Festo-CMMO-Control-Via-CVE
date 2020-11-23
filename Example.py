from Gantry import Gantry

'''
    program to use the Gantry library in order to control a three axis gantry with X, Y, and Z axis.
    
    Additional horizontal or vertical axis can be added easily by adding addition IP address to either 
    the Horizontal or Vertical Axes List. 
'''

x_CMMO_ip_address = "172.21.48.20"  # ip address of the CMMO controlling the x axis
y_CMMO_ip_address = "172.21.48.22"  # ip address of the CMMO controlling the y axis
z_CMMO_ip_address = "172.21.48.24"  # ip address of the CMMO controlling the z axis

horizontalAxes = [x_CMMO_ip_address, y_CMMO_ip_address]  # list of horizontal CMMO IP's
verticalAxes = [z_CMMO_ip_address] # list of vertical CMMO IP's

gantry = Gantry(horizontalAxes, verticalAxes)  # Gantry(list of horizontal axis CMMO IP Addresses,
                                               # list of vertical axis CMMO IP Addresses)
gantry.enable()  # Turn on the motors. Must enable the gantry in order to move or home.
gantry.home()  # Homes all axis of the gantry


def checkDigit(digit_str):  # check if a string can be converted to an int
    try:
        int(digit_str)
    except:
        return False

    return True


while True:  # Infinite loop
    inp = input("Input coordinate (x y z) or H (home) or D (disconnect): ") # get user input
    if 'H' in inp:
        gantry.home()  # Home gantry
    if 'D' in inp:
        gantry.disconnect()  # Disconnect from CMMO
        exit(0)

    inp = inp.split(" ")
    if len(inp) == 3 and checkDigit(inp[0]) and checkDigit(inp[1]) and checkDigit(inp[2]): # check user input
        x = int(inp[0])
        y = int(inp[1])
        z = int(inp[2])
        gantry.moveTo([x, y], [z])  # moveTo(list of locations for horizontal axis, list of locations for vertical axis)
                                    # use -1 to keep an axis in the same location
    else:
        print("invalid input, try again")