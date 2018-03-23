//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~INCLUDES~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#include "mbed.h"
#include "Crypto.h" // Library used for Bitcoin mining.
#include "rtos.h"   // Real time operating system library for threads etc.




//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~DEFINITIONS~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

//~~~~~~~~~~~~~~Photointerrupter pins~~~~~~~~~~~~~~
#define I1pin D2
#define I2pin D11
#define I3pin D12


////~~~~~~~~~~Incremental encoder pins//~~~~~~~~~~~
#define CHA   D7
#define CHB   D8  


//~~Motor Drive output pins~/Mask in output byte~~~
#define L1Lpin D4           //0x01
#define L1Hpin D5           //0x02
#define L2Lpin D3           //0x04
#define L2Hpin D6           //0x08
#define L3Lpin D9           //0x10
#define L3Hpin D10          //0x20


//~~~~~~~~Maximum command length accepted~~~~~~~~~~~
#define MAXCMDLENGTH 18


//~~~~~~~~Maximum PWM allowed due to 50% restriction
#define MAXPWM 1000


//~~~~~~~Enumeration of message identifiers~~~~~~~~~
enum MsgCode {Msg_motorState, Msg_hashRate, Msg_nonceMatch, Msg_keyAdded, Msg_velocityOut, Msg_velocityIn,  Msg_positionIn, Msg_positionOut, Msg_rotations, Msg_torque, Msg_error};


//~~~~~~~New data type to carry the messages~~~~~~~~
typedef struct {
    MsgCode code;
    uint32_t data;
} message_t;



//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Global Variables~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

//Mapping from sequential drive states to motor phase outputs
/*
State   L1  L2  L3
0       H   -   L
1       -   H   L
2       L   H   -
3       L   -   H
4       -   L   H
5       H   L   -
6       -   -   -
7       -   -   -
*/


//~~~~~~~~~~~Drive state to             output table~~~~~~~~~~~~
const int8_t driveTable[] = {0x12,0x18,0x09,0x21,0x24,0x06,0x00,0x00};


//Mapping from interrupter inputs to sequential rotor states. 0x00 and 0x07 are not valid.
const int8_t stateMap[] = {0x07,0x05,0x03,0x04,0x01,0x00,0x02,0x07};  
//Alternative if phase order of input or drive is reversed.
//const int8_t stateMap[] = {0x07,0x01,0x03,0x02,0x05,0x00,0x04,0x07};


////~~~~~~~~~Phase lead to make motor spin~~~~~~~~~
int8_t lead = 2;  //2 for forwards, -2 for backwards


//~~~~~~~~~~~~~~~~~~Rotor states~~~~~~~~~~~~~~~~~~~
int8_t orState = 0;              // Rotor offset at motor state 0 
volatile int8_t intStateOld = 0; // Motor old state. Type is volatile since
                                 // its value may change in ISR 


//~~~~~~~~~~~~~~~~~~~Status LED~~~~~~~~~~~~~~~~~~~~
DigitalOut led1(LED1);


//~~~~~~~~~~~~~Photointerrupter inputs~~~~~~~~~~~~~
InterruptIn I1(I1pin);
InterruptIn I2(I2pin);
InterruptIn I3(I3pin);


//~~~~~~~~~~~~~~Motor Drive outputs~~~~~~~~~~~~~~~~
PwmOut     L1L(L1Lpin);
DigitalOut L1H(L1Hpin);
PwmOut     L2L(L2Lpin);
DigitalOut L2H(L2Hpin);
PwmOut     L3L(L3Lpin);
DigitalOut L3H(L3Hpin);


//~Dats structure to pass information between threads~
Mail<message_t,16> outMessages;


//~~~~~~~~~~~~~~~~~~~~Queue~~~~~~~~~~~~~~~~~~~~~~~~
Queue<void, 8> inCharQ;


//~~~~~~~~~~~~Serial command buffer~~~~~~~~~~~~~~~
char newCmd[MAXCMDLENGTH];
volatile uint8_t cmdIndx = 0;


//~~~~~~~~~~Key to be passed for mining~~~~~~~~~~~
volatile uint64_t newKey;   // Key
Mutex newKey_mutex;         // Restrict access to prevent deadlock.


//~~~~~~~~~~~~~~Initial conditions~~~~~~~~~~~~~~~~
volatile uint32_t motorPower = 300; // motor toque
volatile float targetVel = 45.0;
volatile float targetRot = 459.0;


//~~~~~~~~~~~Motor position variable~~~~~~~~~~~~~~
volatile int32_t motorPos; // Motor position updated by interrupt.


//~~~~~~~~~~Serial port connection~~~~~~~~~~~~~~~~
RawSerial pc(SERIAL_TX, SERIAL_RX);




//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Threads~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thread commOutT(osPriorityAboveNormal,1024);  // Output to serial port.
Thread commInT(osPriorityAboveNormal,1024);   // Input from serial port.
Thread motorCtrlT(osPriorityNormal,1024);     // Motor control thread.




//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Function declarations~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

void motorOut(int8_t driveState, uint32_t pw);
inline int8_t readRotorState();
int8_t motorHome();
void motorISR();
void cmdParser();
void commOutFn();
void putMessage(MsgCode code, uint32_t data);
void serialISR();
void commInFn();
void motorCtrlFn();
void motorCtrlTick(); 




//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Main~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

int main() {
    //~~~~~~~~~~~~~Initial serial prints~~~~~~~~~~~~~
    pc.printf("\n\r\n\r Hello \n\r");
    pc.printf("\n\r\n\rGroup: IndiCorp \n\r");
    pc.printf("Initial hardcoded conditions:\n\r");
    pc.printf("\tVelocity:\t%f\n\r", targetVel);
    pc.printf("\tRotation:\t%f\n\r", targetRot);    
   

    //~~~~~~~~~~~~~~~Start all threads~~~~~~~~~~~~~~~
    commOutT.start(commOutFn);
    commInT.start(commInFn);
    motorCtrlT.start(motorCtrlFn);
    
   
    //~~~~~~~~~~~~~~Attach ISR to serial~~~~~~~~~~~~
    pc.attach(&serialISR);
    
   
    //~~~~~~~~Attach ISR to photointerrupters~~~~~~~
    I1.rise(&motorISR);
    I1.fall(&motorISR);
    I2.rise(&motorISR);
    I2.fall(&motorISR);
    I3.rise(&motorISR);
    I3.fall(&motorISR);
    

    //~~~~~~~~~Declare Bitcoin Variables~~~~~~~~~~~
    SHA256 sha256Inst;
    uint8_t sequence[] = {\
        0x45,0x6D,0x62,0x65,0x64,0x64,0x65,0x64,\
        0x20,0x53,0x79,0x73,0x74,0x65,0x6D,0x73,\
        0x20,0x61,0x72,0x65,0x20,0x66,0x75,0x6E,\
        0x20,0x61,0x6E,0x64,0x20,0x64,0x6F,0x20,\
        0x61,0x77,0x65,0x73,0x6F,0x6D,0x65,0x20,\
        0x74,0x68,0x69,0x6E,0x67,0x73,0x21,0x20,\
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,\
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint64_t* key = (uint64_t*)((int)sequence + 48);
    uint64_t* nonce = (uint64_t*)((int)sequence + 56);
    uint8_t hash[32];
    uint32_t sequenceLength = 64;
    uint32_t hashCounter = 0;
    Timer bitcoinTimer;

    
    //Set PWM period to max 2000 due to hardware limitations
    L1L.period_us(2000); 
    L2L.period_us(2000);
    L3L.period_us(2000);
    

    /* Run the motor synchronisation: orState is subtracted from future rotor
       state inputs to align rotor and motor states */
    orState = motorHome();
    pc.printf("Rotor origin: %x\n\r", orState); //Print state for debugging purposes.
    
   
    //~~~~~~Give the motor a kick to begin~~~~~~~~
    motorISR();
    


    //~~~~~~~~~~~~~~~~Mining loop~~~~~~~~~~~~~~~~~
    bitcoinTimer.start();          // start timer
    while (1) {
        newKey_mutex.lock();
        (*key) = newKey;
        newKey_mutex.unlock();
        sha256Inst.computeHash(hash, sequence, sequenceLength);
        hashCounter++;
        if ((hash[0]==0) && (hash[1]==0)){
            putMessage(Msg_nonceMatch, *nonce);   // matching nonce
        }

        (*nonce)++;

        if (bitcoinTimer.read() >= 1){
            putMessage(Msg_hashRate, hashCounter);
            hashCounter=0;
            bitcoinTimer.reset();
        }
    }
}

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Functions Definitions~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

//~~~~~~~~~~~~Set a given drive state~~~~~~~~~~~~
void motorOut(int8_t driveState, uint32_t pw){

    //Lookup the output byte from the drive state.
    int8_t driveOut = driveTable[driveState & 0x07];
      
    //Turn off first
    if (~driveOut & 0x01) L1L.pulsewidth_us(0);
    if (~driveOut & 0x02) L1H = 1;
    if (~driveOut & 0x04) L2L.pulsewidth_us(0);
    if (~driveOut & 0x08) L2H = 1;
    if (~driveOut & 0x10) L3L.pulsewidth_us(0);
    if (~driveOut & 0x20) L3H = 1;
    
    //Then turn on
    if (driveOut & 0x01) L1L.pulsewidth_us(pw);
    if (driveOut & 0x02) L1H = 0;
    if (driveOut & 0x04) L2L.pulsewidth_us(pw);
    if (driveOut & 0x08) L2H = 0;
    if (driveOut & 0x10) L3L.pulsewidth_us(pw);
    if (driveOut & 0x20) L3H = 0;
}
    

//~Convert photointerrupter inputs to a rotor state~
inline int8_t readRotorState(){
    return stateMap[I1 + 2*I2 + 4*I3];
}

//~~~~~~Basic motor synchronisation routine~~~~~~   
int8_t motorHome() {
    //Put the motor in drive state 0 and wait for it to stabilise
    motorOut(0, MAXPWM); // set to max PWM
    wait(2.0);
    
    //Get the rotor state
    return readRotorState();
}


//~~~~~~~~~Motor ISR (photointerrupters)~~~~~~~~~
void motorISR() {
    static int8_t oldRotorState;
    int8_t rotorState = readRotorState();
    
    motorOut((rotorState-orState+lead+6)%6,motorPower);
    
    // update motorPosition and oldRotorState
    if (rotorState - oldRotorState == 5) motorPos--;
    else if (rotorState - oldRotorState == -5) motorPos++;
    else motorPos += (rotorState - oldRotorState);
    oldRotorState = rotorState;
}


//~~~~~Decode messages to print on serial port~~~~~
void commOutFn() {
    while(1) {
        osEvent newEvent = outMessages.get();
        message_t *pMessage = (message_t*)newEvent.value.p;

        //Case switch to choose serial output based on incoming message
        switch(pMessage->code) {
            case Msg_motorState:
            pc.printf("The motor is currently in state %x\n\r", pMessage->data);
                break;
            case Msg_hashRate:
            pc.printf("Mining at a rate of %.2f Hash/s\n\r", (int32_t)pMessage->data);
                break;
            case Msg_nonceMatch:
                 pc.printf("Nonce found: %x\n\r", pMessage->data);
                break;
            case Msg_keyAdded:
                pc.printf("New key added:\t0x%016x\n\r", pMessage->data);
                break;
            case Msg_torque:
                pc.printf("Motor torque set to:\t%d\n\r", pMessage->data);
                break;
            case Msg_velocityIn:
                pc.printf("Target velocity set to:\t%.2f\n\r", targetVel);
                break;
            case Msg_velocityOut:
                pc.printf("Current Velocity:\t%.2f\n\r", \
                    (float)((int32_t)pMessage->data / 6));
                break;
            case Msg_positionIn:
                pc.printf("Target rotation set to:\t%.2f\n\r", \
                    (float)((int32_t)pMessage->data / 6));
                break;
            case Msg_positionOut:
            pc.printf("Current position:\t%.2f\n\r", \
           (float)((int32_t)pMessage->data / 6));
                break;
            case Msg_error:
                pc.printf("Debugging position:%x\n\r", pMessage->data);
                break;
            default:
            pc.printf("Unknown Error. Data: %x\n\r", pMessage->data);
                break;
        }
        outMessages.free(pMessage);
    }
}


//~~~~~~~~~Put message in Mail queue~~~~~~~~~~~
void putMessage(MsgCode code, uint32_t data){
    message_t *pMessage = outMessages.alloc();
    pMessage->code = code;
    pMessage->data = data;
    outMessages.put(pMessage);
}


//~~~~Receive & decode serial input command~~~~~
void commInFn() {
    while (1) {
        osEvent newEvent = inCharQ.get();
        uint8_t newChar = *((uint8_t*)(&newEvent.value.p));
        pc.putc(newChar);
        if(cmdIndx >= MAXCMDLENGTH){            //Make sure there is no overflow in comand.
            cmdIndx = 0;
            putMessage(Msg_error, 1);
        }
        else{
            if(newChar != '\r'){                //While the command is not over, 
                newCmd[cmdIndx] = newChar;      //save input character and
                cmdIndx++;                      //advance index
            }
            else{
                newCmd[cmdIndx] = '\0';         //When the command is finally over,
                cmdIndx = 0;                    //reset index and
                cmdParser();                    //parse the command for decoding.
            }
        }
    }
}



//~~~~~~~~~~~~~Decode the command~~~~~~~~~~~
void cmdParser(){
        switch(newCmd[0]) {
                case 'K':
                        newKey_mutex.lock();                        //Ensure there is no deadlock
                        sscanf(newCmd, "K%x", &newKey);             //Find desired the Key code
                        putMessage(Msg_keyAdded, newKey);           //Print it out
                        newKey_mutex.unlock();                      
                        break;
                case 'V':
                        sscanf(newCmd, "V%f", &targetVel);          //Find desired the target velocity
                        putMessage(Msg_velocityIn, targetVel);      //Print it out
                        break;
                case 'R':
                        sscanf(newCmd, "R%f", &targetRot);          //Find desired target rotation
                        putMessage(Msg_positionIn, targetRot);      //Print it out
                        break;
                case 'T':
                        sscanf(newCmd, "T%d", &motorPower);         //Find desired target torque
                        putMessage(Msg_torque, motorPower);         //Print it out
                        break;
                default: break;
        }
}


//~~~~~~~~~~~~~Serial ISR~~~~~~~~~~~~
void serialISR() {
    uint8_t newChar = pc.getc();
    inCharQ.put((void*)newChar);
}


//~~~~~~ISR triggered by Ticker~~~~~~
void motorCtrlTick(){
    motorCtrlT.signal_set(0x1);                            //Set signal to motor control thread which carries out calculations to avoid CPU blocking
}


//~~~~~~~~~~~~~Motor control function  with proportional controller~~~~~~~~~~~
void motorCtrlFn() {

    //~~~~~~~~~~~~~Variables~~~~~~~~~~~~~~~~
    Ticker motorCtrlTicker;                             //Ticker to ba attached to callback function
    int32_t velocity;                                   //Variable for local velocity calculation
    int32_t locMotorPos;                                //Local copy of motor position
    static int32_t oldMotorPos = 0;                     //Old motor position used for calculations
    static uint8_t motorCtrlCounter = 0;                //Counter to be reset every 10 iterations to get velocity calculation in seconds
    int32_t torque;                                     //Local variable to set motor torque
    float sError;                                       //Velocity error between target and reality
    float rError;                                       //Rotation error between target and reality
    static float rErrorOld;                             //Old rotation error used for calculation

    //~~~Controller constants~~~~
    int32_t Kp1=22;                                     //Proportional controller constants 
    int32_t Kp2=22;                                     //Calculated by trial and error to give optimal accuracy  
    float   Kd=15.5;    
       

    //Attach ticker to callback function that will run every 100 ms
    motorCtrlTicker.attach_us(&motorCtrlTick,100000);



    while(1) {
        motorCtrlT.signal_wait(0x1);                    // Wait for thread signal.

        //Initial velocity calculation and report
        locMotorPos = motorPos;                         //Read global variable motorPos which is updated by interrupt and store it in local variable
        velocity = (locMotorPos - oldMotorPos) * 10;    //Proceed with calculation
        oldMotorPos = locMotorPos;                      //Update old motor position
        motorCtrlCounter++;                             //Advance counter 
        if (motorCtrlCounter >= 10) {                   //Every 10th iteration
            motorCtrlCounter = 0;                       //Reset counter
            putMessage(Msg_velocityOut, velocity);      //Report the current velocity
            putMessage(Msg_positionOut, locMotorPos);   //Report the current position
        }
        
        //~~~~~Speed controller~~~~~~
        sError = (targetVel * 6) - abs(velocity);        //Read global variable targetVel updated by interrupt and calculate error between target and reality
        int32_t Ys;                                      //Initialise controller output Ys  
        if (sError == -abs(velocity)) {                  //Check if user entered V0, 
            Ys = MAXPWM;                                 //and set the output to maximum as specified
        }
        else {
            Ys = (int)(Kp1 * sError);                    //If the user didn't enter V0 implement controller transfer function: Ys = Kp * (s -|v|) where,
        }                                                //Ys = controller output, Kp = prop controller constant, s = target velocity and v is the measured velocity
        
        //~~~~~Rotation control~~~~~~
        rError = targetRot - (locMotorPos/6);            //Read global variable targetRot updated by interrupt and calculate the rotation error. 
        int32_t Yr;                                      //Initialise controller output Yr
        Yr = Kp2*rError + Kd*(rError - rErrorOld);       //Implement controller transfer function Ys= Kp*Er + Kd* (dEr/dt)        
        rErrorOld = rError;                              //Update rotation error
        if(rError < 0){                                  //Use the sign of the error to set controller wrt direction of rotation
            Ys = -Ys;                               
        }

        if((velocity>=0 && Ys<Yr) || (velocity<0 && Ys>Yr)){        //Choose Ys or Yr based on distance from target value so that it takes 
            torque = Ys;                                            //appropriate steps in the right direction to reach target value
        }
        else{
            torque = Yr;
        }
        if(torque < 0){                                             //Variable torque cannot be negative since it sets the PWM  
            torque = -torque;                                       //Hence we make the value positive, 
            lead = -2;                                              //and instead set the direction to the opposite one
        }
        else{
            lead = 2;
        }
        if(torque > MAXPWM){                                        //In case the calculated PWM is higher than our maximum 50% allowance,
            torque = MAXPWM;                                        //Set it to our max.
        }   
        motorPower = torque;                                        //Lastly, update global variable motorPower which is updated by interrupt        
    }
}
