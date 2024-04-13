#!/usr/bin/python3           # This is client.py file

import socket
import traceback

# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# s.connect(("128.186.120.158", 31530))
# s.connect(("128.186.120.158", 31536))
s.connect(("128.186.120.158", 31537))

BLOCK_SIZE = 16 # block size - default is 16 bytes
BYTE_SIZE = 2 # 1 hex byte represented as 2 chars

def byte_values():
    # all 256 possible hex bytes
    hex_values = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
    possible_bytes_values = []
    for value1 in hex_values:
        for value2 in hex_values:
            possible_bytes_values.append(value1 + value2)
    return possible_bytes_values

ALL_POSSIBLE_BYTE_VALUES = byte_values()

def get_str_from_hex(hex_str):
    # get ascii string characters from the given hex string characters
    return bytes.fromhex(hex_str[2:]).decode('utf-8')

def get_hex(num):
    # get hex string characters for given decimal number
    h = hex(num)
    if len(h) > 3:
        return h
    else:
        return h[0:2] + "0" + h[2:]

def get_message(message, flag=False):
    # get string message from int bytes
    m = ''
    for i in range(len(message)):
        if flag:
            if i >= messageLength:
                return m
        if message[i] == '_':
            m += '_'
        else:
            m += get_str_from_hex(get_hex(message[i]))
    return m

def get_blocks(st):
    # get blocks of data from a string
    start = 0
    end = BLOCK_SIZE * BYTE_SIZE
    blocks = []
    for i in range(1,len(st)//(BLOCK_SIZE * BYTE_SIZE)+1):
        blocks.append(st[start:end])
        start += BLOCK_SIZE * BYTE_SIZE
        end += BLOCK_SIZE * BYTE_SIZE
    if end < len(st):
        blocks.append(s[end:])
    return blocks

def parse_result_e(result, flag=False):
    # parse encrypted resut
    # print(result)
    lines = result.splitlines()
    if len(lines) < 3:
        return None
    enc = lines[0] # b‘Encryption: 80\n49 8d 8e 57 ...6a 3d de \n’
    start, end = 14, 14
    for i in range(start,len(enc)):
        if enc[i] == '\\':
            end = i
            break
    length = enc[start:end]
    c = enc[end+2:len(enc)-4]
    c = c.replace(" ", "")
    # TODO: Can we assume encrypted c will be in one line?
    iv = lines[1][6:-1] #  IV: b‘a5244e79b9f94b4f5634a8b00e06e46c’
    if flag:
        print(lines[2])
        print("length \t: ", int(length))
        print("c \t: ", get_blocks(c))
        print("iv \t: ", iv)
    return int(length), c, iv

def parse_result_v(result, flag=True):
    # parse verification result
    if flag:
        print(result)
    if result == "Valid" or result == "valid":
        return 1
    elif result == "Invalid: Wrong Pad":
        return 2
    elif result == "Invalid: Wrong Tag":
        return 3
    else:
        return 4

try:
    # find length of mesage first
    print("\nTrying to find length of secret first ...\n")
    length = 0
    dataToFindLength = "-e "
    dummyDataToAdd = "01"
    emptyLength = -1 # init value
    resultLengthOld = -1 # init value
    resultLengthNew = -1 # init value
    while resultLengthOld == -1 or resultLengthOld == resultLengthNew:
        if length == 0:
            data = dataToFindLength
        else:
            data = dataToFindLength + dummyDataToAdd*length
        print(data)
        s.send(data.encode())
        result = s.recv(1024).decode()
        resultLengthOld = resultLengthNew
        resultLengthNew, c, iv = parse_result_e(result)
        if resultLengthOld == -1:
            emptyLength = resultLengthNew
        length += 1
    messageLength = emptyLength - BLOCK_SIZE - (length - 1)
    print("\nLength of secret message must be " + str(messageLength) + " bytes\n")

    # first send empty message
    data = dataToFindLength
    s.send(data.encode())
    result = s.recv(1024).decode()
    l, c , iv = parse_result_e(result)
    paddingLength = BLOCK_SIZE - messageLength % BLOCK_SIZE
    print("\nLength of padding must be " + str(paddingLength) + " bytes\n")

    # now attack
    print("\nRecovering secret using padding oracle attack now ...\n")
    verificationResult = -1 # init
    message = ["_"] * (l - BLOCK_SIZE)
    possibleValuesIter = 0
    byteIndex = BLOCK_SIZE - 1
    p_prime_byte = 0
    iv_c = iv + c
    iv_c_prime = iv_c
    iv_c_prime = iv_c_prime[0:-32]
    print("iv_c \t\t: ", get_blocks(iv_c))
    print("iv_c_prime \t: ", get_blocks(iv_c_prime))
    total_iv_c_prime_blocks = len(get_blocks(iv_c_prime))
    blockIndex = total_iv_c_prime_blocks - 1 - 1

    while blockIndex >= 0 and byteIndex >= 0 and verificationResult != 3 and possibleValuesIter < len(ALL_POSSIBLE_BYTE_VALUES):
        # print(blockIndex, byteIndex, possibleValuesIter)
        byteValue = ALL_POSSIBLE_BYTE_VALUES[possibleValuesIter]
        byteIndexStart = (blockIndex * BLOCK_SIZE * BYTE_SIZE) + (byteIndex * BYTE_SIZE)
        byteIndexEnd = byteIndexStart + BYTE_SIZE
        iv_c_prime = iv_c_prime[0:byteIndexStart] + byteValue + iv_c_prime[byteIndexEnd:]
        # print("iv_c_prime \t: ", get_blocks(iv_c_prime))

        # send prime cipher for verification
        data = "-v " + iv_c_prime[(BLOCK_SIZE*BYTE_SIZE):] + " " + iv_c_prime[0:(BLOCK_SIZE*BYTE_SIZE)]
        # print(data)
        s.send(data.encode())
        result = s.recv(1024).decode()
        verificationResult = parse_result_v(result, False)
        # print(verificationResult)

        if verificationResult == 3:
            iv_c_byte = int(iv_c[byteIndexStart:byteIndexEnd], 16)
            iv_c_prime_byte = int(byteValue, 16)
            p_byte = iv_c_byte ^ iv_c_prime_byte ^ p_prime_byte
            message[(blockIndex * BLOCK_SIZE) + byteIndex] = p_byte
            print("\niv_c \t\t: ", get_blocks(iv_c))
            print("iv_c_prime \t: ", get_blocks(iv_c_prime))
            print("block index \t\t: ", blockIndex)
            print("byte index \t\t: ", byteIndex)
            print("iv_c_byte \t\t: ", get_hex(iv_c_byte))
            print("iv_c_prime_byte \t: ", get_hex(iv_c_prime_byte))
            print("p_prime_byte \t\t: ", get_hex(p_prime_byte))
            print("plain byte \t\t: ", get_hex(p_byte))
            print("plain message \t: ", get_message(message,True))
            print()

            # prepare for next byte iteration
            possibleValuesIter = 0
            verificationResult = -1
            p_prime_byte += 1
            # modify iv_c_prime
            i = BLOCK_SIZE - 1
            while i >= byteIndex:
                byteIndexStart = (blockIndex * BLOCK_SIZE * BYTE_SIZE) + (i * BYTE_SIZE)
                byteIndexEnd = byteIndexStart + BYTE_SIZE
                iv_c_prime_byte =  p_prime_byte ^ message[(blockIndex*BLOCK_SIZE)+i] ^ int(iv_c[byteIndexStart:byteIndexEnd],16)
                iv_c_prime = iv_c_prime[0:byteIndexStart] + get_hex(iv_c_prime_byte)[2:] + iv_c_prime[byteIndexEnd:] 
                i -= 1
            byteIndex -= 1
            if byteIndex < 0:
                blockIndex -= 1
                byteIndex = BLOCK_SIZE - 1
                iv_c = iv_c[0:-32]
                iv_c_prime = iv_c
                iv_c_prime = iv_c_prime[0:-32]
                p_prime_byte = 0
            print("new iv_c_prime \t: ", get_blocks(iv_c_prime))
        else:
            possibleValuesIter += 1
    
    if possibleValuesIter == len(ALL_POSSIBLE_BYTE_VALUES):
        print("\nCouldn't retreive secret. All possible values exhausted.\n")
        
    print("\nSecret message is :\n")
    print(get_message(message,True))
    print()

except Exception as e:
    print("\nException occured")
    print(traceback.format_exc())

finally:
    print("\nClosing socket\n")
    s.close()
