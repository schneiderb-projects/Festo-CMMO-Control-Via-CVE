# Festo-CMMO-Control-Via-CVE

This is a library providing an easy API to communicate with and control a Festo CMMO via Python. To see the library in action, see Example.py.

Files Descriptions:

    Gantry.py: Top level API to be used to control any number of Festo CMMO's with both Vertical and Horizontal Axes.
  
    CMMO.py: API for controlling an individual CMMO. Don't use this unless you are experienced with the CMMOs and need additional functionality not provided by Gantry.py
  
    CVE.py: Low Level communication between the CMMO and your computer using the CVE protocol. This contains all of the packet structures for the CVE protcol.
