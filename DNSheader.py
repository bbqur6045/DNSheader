#Python 3.6 ver
# name : DNS header parser
#-*- coding : utf-8 -*-

import sys
import struct

f = open(sys.argv[1], 'rb')
f.seek(0)
sp = f.read(12)


print("Transaction ID : ", hex(struct.unpack_from(">H", sp, 0x00)[0]))
Flags  = (bin(struct.unpack_from(">H",sp, 0x02)[0]))

print ("------------------------ Flags ------------------------")
QR = (Flags[:1])
opcode = (Flags[1:5])
AA = (Flags[5])
TC = (Flags[6])
RD = (Flags[7])
RA = (Flags[8])
Z = (Flags[9:12])
rcode = (Flags[12:16])

'''print (QR)
print (opcode)
print (AA)
print (TC)
print (RD)
print (RA)
print (Z)
print (rcode)'''
# QR 은 0일때 Query를 뜻하고 1 일때는 Response이다.
if QR == '0' :
    print ("QR : " + QR + " Query")
else :
    print("QR : " + QR + " Response")

#opcode 는 쿼리의 유형을 지정함과 동시에 코드별로의 상태를 확인한다.
if opcode == 'b000' :
    print ("Opcode : " + opcode + " / state : Query") # 질의문
elif opcode == 'b001' :
    print ("Opcode : " + opcode + " / state : Inverse Query") # 역 질의문
elif opcode == 'b010' :
    print ("Opcode : " + opcode + " / state : Status") # 서버의 상태 요구
elif opcode == 'b011' :
    print ("Opcode : " + opcode + " / state : Unassigned") # 통지
elif opcode == 'b100' :
    print ("Opcode : " + opcode + " / state : Notify") # 통지
elif opcode == 'b101' :
    print ("Opcode : " + opcode + " / state : Update") # 갱신
else :
    print ("Opcode : " + opcode + " / state : Unassigned") # 현재 사용되지않는 코드

print ("Authoritative : " + AA )# 공식 DNS 패킷의 Reponse에만 셋팅이 되어있다. 
print ("Truncated : " + TC ) # DNS 응답 길이가 512byte넘을 경우 패킷이 잘린다. 그럴때 표시하는 TCP로 다시 전송하게 된다.
print ("Recursion Desired : " + RD) #재귀 쿼리의 필요 여부를 판단한다.
print ("Recursion available : " + RA) # 응답한 DNS서버가 재귀 질의로 표시되며 Response시에만 표시
print ("Z : " + Z) #예약된 필드로 0으로 셋팅되어있다.

if rcode == '0000':
    print("rcode : " + rcode + " / state : NoError") # 오류 없음
elif rcode == '0001':
    print("rcode : " + rcode + " / state : FormErr") # 형식 오류 (쿼리가 잘못된 경우)
elif rcode == '0010':
    print("rcode : " + rcode + " / state : ServFail") # 서버 실패 (DNS 서버 자체의 문제로 실패)
elif rcode == '0011':
    print("rcode : " + rcode + " / state : NXDomain") # 네임 오류 (도메인 네임이 존재하지 않을 경우)
elif rcode == '0100':
    print("rcode : " + rcode + " / state : NotImp") # DNS 서버가 Query를 지원하지 못함
else :
    print("rcode : " + rcode + " / state : Refused") # 거부 (정책적인 이유로 Query를 거절함)

print ("------------------------ Question Count ------------------------")
# Question Count 는 질문의 섹션 개수를 표시한다. Query 패킷당 하나의 질문을 볼 수 있다.
print ('Question Count : ' ,hex(struct.unpack_from(">H",sp,0x04)[0]))

print ("------------------------ Answer Count ------------------------")
# Answer Count는 응답 개수를 표시한다.
print ('Answer Count : ' , hex(struct.unpack_from(">H",sp,0x06)[0]))

print ("------------------------ Name Server ------------------------")
# 똑같이 책임 리코드 개수를 표시한다.
print (' Name Server : ', hex(struct.unpack_from(">H",sp,0x08)[0]))

print ("------------------------ Additional Information ------------------------")
# 부가정보 레코드 카운터이다.
print (' Additional Information : ' , hex(struct.unpack_from(">H",sp,0xA)[0]))
