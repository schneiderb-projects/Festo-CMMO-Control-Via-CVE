from Gantry import Gantry

'''
    program to use the Gantry library in order to control a three axis gantry with X, Y, and Z axis.
    
    Additional axes can be added easily by adding addition IP address when initializing
'''

x_CMMO_ip_address = "172.21.48.20"  # ip address of the CMMO controlling the x axis
y_CMMO_ip_address = "172.21.48.22"  # ip address of the CMMO controlling the y axis
z_CMMO_ip_address = "172.21.48.24"  # ip address of the CMMO controlling the z axis

all_axes = [x_CMMO_ip_address, y_CMMO_ip_address, z_CMMO_ip_address]

gantry = Gantry(all_axes)  # Gantry(list of CMMO ip addresses)
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
    split_inp = inp.split(" ")
    if 'H' in inp:
        gantry.home()  # Home gantry
    elif 'D' in inp:
        gantry.disconnect()  # Disconnect from CMMO
        exit(0)
    elif len(split_inp) == 3 and checkDigit(split_inp[0]) and checkDigit(split_inp[1]) and checkDigit(split_inp[2]): # check user input
        x = int(split_inp[0])
        y = int(split_inp[1])
        z = int(split_inp[2])
        gantry.moveTo([x, y, z])  # moveTo(list of locations)
                                  # use -1 to keep an axis in the same location
    else:
        print("invalid input, try again")
