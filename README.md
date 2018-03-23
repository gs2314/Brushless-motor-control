# EmbeddedSystemsCW2
Second coursework for EE3-24

User Manual

Due to a hardware issue with the photointerrupters it is best to operate the motor in a dark room. Tuning was performed with a napkin covering the top of the motor to block part of the lighting on motor number 31.

Sometimes due to the rotor starting in the wrong position the controller can bug and force the actual value to diverge far from the target. In such a case, hold the reset button down until the disc stops spinning and release.

If the motor is stuck, give it a gentle push and it should start immediately. This is due to the weak motor fields developing too little torque.

Initially, the code has hardcoded values for target position and rotation as a first demonstration. They can be overwritten by an input command of your choice on the terminal.

List of commands:
R – Rotation command followed by the desired number of rotations
V – Velocity command followed by the desired velocity 
K – Bitcoing mining key command followed by the desired key
T – Torque command followed by the desired torque

