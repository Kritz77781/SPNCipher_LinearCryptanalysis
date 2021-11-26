# Linear cryptanalysis of the SPN cipher 

# Determining linear expressions between the input and output bits which have a linear probability bias. 
# Randomly chosen bits would only satisfy the expression with probability 0.5 (Matsui's Piling up Lemma)

import basic_SPN as cipher
from math import trunc, fabs
import itertools as it
import collections

# Build table of input values
sBox_input = ["".join(seq) for seq in it.product("01", repeat=4)]
# Build a table of output values
sBox_output = [ bin(cipher.sBox[int(seq,2)])[2:].zfill(4) for seq in sBox_input ]
# Build an ordered dictionary between input and output values
sBox_b = collections.OrderedDict(zip(sBox_input,sBox_output))
# Initialise the Linear Approximation Table (LAT)
probabilityBias = [[0 for x in range(len(sBox_b))] for y in range(len(sBox_b))] 

# A complete enumeration of all the linear approximations of the simple SPN
# cipher S-Box. Dividing an element value by 16 gives the probability bias 
# for the particular linear combination of input and output bits.
print('Linear Approximation Table for SPN cipher\'s sBox: ')
print('(x-axis: output equation - 8; y-axis: input equation - 8)')
for bits in sBox_b.items():
    input_bits, output_bits = bits
    X1,X2,X3,X4 = [ int(bits,2) for bits in [input_bits[0],input_bits[1],input_bits[2],input_bits[3]] ]
    Y1,Y2,Y3,Y4 = [ int(bits,2) for bits in [output_bits[0],output_bits[1],output_bits[2],output_bits[3]] ]
                
    equations_in = [0, X4, X3, X3^X4, X2, X2^X4, X2^X3, X2^X3^X4, X1, X1^X4,
                    X1^X3, X1^X3^X4, X1^X2, X1^X2^X4, X1^X2^X3, X1^X2^X3^X4] 
                    
    equations_out = [0, Y4, Y3, Y3^Y4, Y2, Y2^Y4, Y2^Y3, Y2^Y3^Y4, Y1, Y1^Y4,
                    Y1^Y3, Y1^Y3^Y4, Y1^Y2, Y1^Y2^Y4, Y1^Y2^Y3, Y1^Y2^Y3^Y4]                
    
    for x_idx in range (0, len(equations_in)):
        for y_idx in range (0, len(equations_out)):
            probabilityBias[x_idx][y_idx] += (equations_in[x_idx]==equations_out[y_idx])

# Print the linear approximation table
for bias in probabilityBias:
    for bia in bias:
        #trunc(((bia/16.0)-0.5)*16.0)
        print('{:d}'.format(bia-8).zfill(2), end=' ')
    print('')
    
# Constructing Linear Approximations for the Complete Cipher.
# It is possible to attack the cipher by recovering a subset of the subkey
# bits that follow the last round.

# Using the LAT, we can construct the following equation that holds with 
# probability 0.75. Let U_{i} and V_{i} represent the 16-bit block of bits
# at the input and output of the round i S-Boxes, respectively, and let 
# K_{i,j} represent the j\'th bit of the subkey block of bits exclusive-ORed
# at the input to round i. Also let P_{i} represent the i\'th input bit, then
#
# U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}⊕SUM(K) = 0 where
#
# SUM(K) = K_{1,5}⊕K_{1,7}⊕K_{1,8}⊕K_{2,6}⊕K_{3,6}⊕K_{3,14}⊕K_{4,6}⊕K_{4,8}⊕K_{4,14}⊕K_{4,16}
# 
# holds with a probability of 15/32 (with a bias of 1/32). 
#
# Since sum(K) is fixed (by the key, k), U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8} = 0
# must hold with a probability of either 15/32 or 1-15/32. In other words we
# now have a linear approximation of the first three rounds of the cipher with
# a bias of magnitude 1/32.

k = cipher.keyGeneration()
k_5 = int(k,16)&0xffff #Just last 16 bits are K5
k_5_5_8 = (k_5>>8)&0b1111
k_5_13_16 = k_5&0b1111

print('\nTest key k = {:}'.format(k), end = ' ')
print( '(k_5 = {:}).'.format(hex(k_5).zfill(4)))
print('Target partial subkey K_5,5...k_5,8 = 0b{:} = 0x{:}'.format(bin(k_5_5_8)[2:].zfill(4), hex(k_5_5_8)[2:].zfill(1) ))
print('Target partial subkey K_5,13...k_5,16 = 0b{:} = 0x{:}'.format(bin(k_5_13_16)[2:].zfill(4), hex(k_5_13_16)[2:].zfill(1) ))
print('Testing each target subley value...')

countTargetBias = [0]*256
num_Attacks = 10000
for plainText in range(num_Attacks):
    cipherText = cipher.encrypt(plainText, k)
    ct_5_8 = (cipherText>>8)&0b1111
    ct_13_16 = cipherText&0b1111
    
    # For each target partial subkey value k_5|k_8|k_13|k_16 in [0,255],
    # increment the count whenever equation (5) holds true,
	
    for target in range(256):
        target_5_8 = (target>>4)&0b1111
        target_13_16 = target&0b1111
        v_5_8 = (ct_5_8^target_5_8)
        v_13_16 = (ct_13_16^target_13_16)
		
        # for target_13_16 in range(16):
        # Does U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}⊕SUM(K) = 0?
             
	    # (1) Compute U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16} by running the ciphertext
	    # backwards through the target partial subkey and S-Boxes. 
	    # xor ciphertext with subKey bits
                
	    # (2) Run backwards through s-boxes
        u_5_8, u_13_16 = cipher.sBox_inverse[v_5_8], cipher.sBox_inverse[v_13_16]
        
        #print(((plainText>>11)&0b1)^((plainText>>9)&0b1)^((plainText>>8)&0b1))
	    # (3) Compute linear approximation U_{4,6}⊕U_{4,8}⊕U_{4,14}⊕U_{4,16}⊕P_{5}⊕P_{7}⊕P_{8}
        linearApprox = ((u_5_8>>2)&0b1)^(u_5_8&0b1)^((u_13_16>>2)&0b1)^(u_13_16&0b1)^((plainText>>11)&0b1)^((plainText>>9)&0b1)^((plainText>>8)&0b1)
        if linearApprox == 0:
            countTargetBias[target] += 1
	         
# The count which deviates the largest from half of the number of
# plaintext/ciphertext samples is assumed to be the correct value.   
bias = [fabs(lAprx - 5000.0)/num_Attacks for lAprx in countTargetBias]

maxResult, maxIndex = 0,0
for rIndex, result in enumerate(bias):
    if result > maxResult:
        maxResult = result
        maxIndex = rIndex

print('Highest bias is {:} for subKey value {:}.'.format(maxResult, hex(maxIndex)))
if (maxIndex>>4)&0b1111 == k_5_5_8 and maxIndex&0b1111 == k_5_13_16:
	print('Success!')
else:
	print('Failure')



