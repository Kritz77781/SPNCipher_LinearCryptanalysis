# Basic SPN cipher which takes a 16-bit block as input and has 4 rounds.
# Each round consists of (1) substitution (2) transposition (3) key mixing

import random
import hashlib

block_size = 16
verboseState = False

# Substitution takes place: 4x4 bijective, one sBox used for all 4 sub-blocks of size 4.
# Non-linear mapping
sBox =     {0:0xE, 1:0x4, 2:0xD, 3:0x1, 4:0x2, 5:0xF, 6:0xB, 7:0x8, 8:0x3, 9:0xA, 0xA:0x6, 0xB:0xC, 0xC:0x5, 0xD:0x9, 0xE:0x0, 0xF:0x7} 
sBox_inverse = {0xE:0, 0x4:1, 0xD:2, 0x1:3, 0x2:4, 0xF:5, 0xB:6, 0x8:7, 0x3:8, 0xA:9, 0x6:0xA, 0xC:0xB, 0x5:0xC, 0x9:0xD, 0x0:0xE, 0x7:0xF}

# Apply sBox to a 16 bit state 
# Return the result
def sBox_apply(state, sBox):
    subStates = [state&0x000f, (state&0x00f0)>>4, (state&0x0f00)>>8, (state&0xf000)>>12]
    for idx,subState in enumerate(subStates):
        subStates[idx] = sBox[subState]
    return subStates[0]|subStates[1]<<4|subStates[2]<<8|subStates[3]<<12
    

# Permutation/transposition takes place which is applied in bit-wise manner
# Output i of S-box j is connected to input j of S-box i
pBox = {0:0, 1:4, 2:8, 3:12, 4:1, 5:5, 6:9, 7:13, 8:2, 9:6, 10:10, 11:14, 12:3, 13:7, 14:11, 15:15}

# Key mixing occurs by bitwise XOR operation between round subkey and data block input to round
# Key schedule: independent random round keys.
# Taking the sha-hash of a 128-bit 'random' seed and then take the first 80-bits 
# of the output as out round keys K1-K5 (Each 16 bits long)
def keyGeneration():
    k = hashlib.sha1( hex(random.getrandbits(128)).encode('utf-8') ).hexdigest()[2:2+20]
    return k

# SPN Cipher encrypt function
def encrypt(plaintext, k):
    state = plaintext
    if verboseState: print('**plaintext = {:04x}**'.format(state))
    
    subKeys = [ int(subK,16) for subK in [ k[0:4],k[4:8], k[8:12], k[12:16], k[16:20] ] ]
    
    #First three rounds of SPN cipher
    for roundN in range(0,3):
    
        if verboseState: print(roundN, end = ' ')
        #XOR state with round key (3, subkeys 1,..,4)
        state = state^subKeys[roundN]
        if verboseState: print (hex(state), end = ' ')
        
        #Break state into nibbles, perform sBox on each nibble, write to state (1)
        state = sBox_apply(state,sBox)
        if verboseState: print (hex(state), end = ' ')
        
        #Permute the state bitwise (2)
        stateTemp = 0      
        for bit_index in range(0,block_size):
            if(state & (1 << bit_index)):
                stateTemp |= (1 << pBox[bit_index])
        state = stateTemp
        if verboseState: print (hex(state))
    
    # Final round of SPN cipher (k4, sBox, s5)
    state = state^subKeys[-2] #penultimate subkey (key 4) mixing
    if verboseState: print (str(3), hex(state), end = ' ')   
    state = sBox_apply(state,sBox)
    if verboseState: print (hex(state), end = ' ')
    state = state^subKeys[-1] #Final subkey (key 5) mixing
    if verboseState: print (hex(state)) 
    if verboseState: print('**ciphertext = {:04x}**'.format(state))
    
    return state

# SPN Cipher decrypt function
def decrypt(ciphertext, k):
    state = ciphertext
    if verboseState: print('**ciphertext = {:04x}**'.format(state))
    
    #Derive round keys
    subKeys = [ int(subK,16) for subK in [ k[0:4],k[4:8], k[8:12], k[12:16], k[16:20] ] ]
    
    if verboseState: print (str(3), hex(state), end= ' ')
    
    #Undo final round key
    state = state^subKeys[4]
    if verboseState: print (hex(state), end= ' ')
    
    #Apply inverse s-box
    state = sBox_apply(state,sBox_inverse)
    if verboseState: print (hex(state))
    
    #Undo first 3 rounds of SPN cipher
    for roundN in range(2, -1, -1):
        
        if verboseState: print(roundN, end = ' ')
        #XOR state with round key (3, subkeys 4,..,0)
        state = state^subKeys[roundN+1]
        if verboseState: print (hex(state), end=' ')
        
        #Un-permute the state bitwise 
        stateTemp = 0      
        for bit_index in range(0, block_size):
            if(state & (1 << bit_index)):
                stateTemp |= (1 << pBox[bit_index])
        state = stateTemp
        if verboseState: print (hex(state), end = ' ')
        
        #Apply inverse s-box
        state = sBox_apply(state,sBox_inverse)
        if verboseState: print (hex(state))
    if verboseState: print(roundN, end = ' ')
    
    #XOR state with round key 0
    state = state^subKeys[0]
    if verboseState: print('**plaintext = {:04x}**'.format(state))     
     
    return state

if __name__ == "__main__":
    
    # Generate a random key 
    k = keyGeneration()
    
    # Produce a CSV of plaintext, key value pairs for cryptanalysis 
    fileName = 'testData/' + k[0:20] + '.dat'
    nVals = 10000
    fd_w = open(fileName,"w")
    print ('Running basic SPN cipher with key K = {:}'.format(k))
    
    #fd_w.write('test')
    for i in range(0, nVals):     
        fd_w.write('{:04x}, {:04x}\n'.format(i, encrypt(i, k)))
    
    fd_w.close()
    
    print ('Simple SPN plaintext, ciphertext CSV written to ' + fileName) 
    print ('{:} values written.'.format(nVals))
    
                 
