;; Program SHA-1 (Secure Hashing)
;; Author : Ahmad Husni (husni_111990290@yahoo.com)
;; Mircoprocessor Laboratory stT Telkom Bandung - Indonesia
;; Date : 19 July 2003
;; Compiler, Linker, Simulator : AVrstudio4 from http://www.atmel.com
;;
;; Modified for use with AVR-GCC by Steve Motto, Atmel Corp.

/* relocatable changes:
 *	shaEngine(ctx->buf, ctx->h);
 * 		R25:R24 --	ctx->buf (ptr to incoming 64 byte message (Wt) -- must
 *					already be padded (512 bits - 65 bits = 447 bits max message)
 * 		R23:R22 --	ctx->h (chaining variables -- 5 U32 sized vars (A-E), big endian,
 *					must be initialized before first call)
 *
 *  	* all fixed references (A0 - E0, Wt) changed to use values passed by calling C
 *  	  function
 *		* save and restore C registers
 *		* save initial H values
 *		* endianness of incoming U32s
 *
 */

//#include <avr/io.h> kmj

.lcomm	pA0, 2			;;; ptrs to 5 chaining variables
.lcomm	pB0, 2
.lcomm	pC0, 2
.lcomm	pD0, 2
.lcomm	pE0, 2
.lcomm	pWt, 2

.lcomm	initAstore, 4	;;; storage for incoming initial H params
.lcomm	initBstore, 4
.lcomm	initCstore, 4
.lcomm	initDstore, 4
.lcomm	initEstore, 4

;;; C function entry point
.global shaEngine
shaEngine:

	rcall saveRegs		;;; save necessary AVR-GCC registers (r2-r17, r28-r29)
	rcall initVarPtrs	;;; initialize A-E ptrs
	rcall saveInitVars	;;; save initial H values

	lds	XH,	pWt+1 	;; Wt ptr
	lds	XL,	pWt
	ldi	r20, 00		;; t=0

LOOP_HASH:

	lds YL, pB0
	lds YH, pB0+1

	;; Compute c = rOTL^30(b)

	ldd	r16, Y+3
	ldd	r17, Y+2
	ldd	r18, Y+1
	ldd	r19, Y+0

	lsr	r19
	ror	r18
	ror	r17
	ror	r16
	brcc NotC1
	ori	r19, 0x80
NotC1:

	lsr	r19
	ror	r18
	ror	r17
	ror	r16
	brcc NotC2
	ori	r19, 0x80
NotC2:
	mov	r2, r16		;; Save new c in r2,r3,r4,r5
	mov	r3, r17
	mov	r4, r18
	mov	r5, r19

	rcall CalculateT ;; a = T = rOTL^5(a) + ft(b,c,d) + e + Kt + Ws
	rcall Update	;; e = d
					;; d = c
					;; c = rOTL^30(b)
					;; b = a
					;; a = T

	adiw XL, 4
	inc	r20
	ldi	r16, 79+1
	cpse r20, r16	;; until t=79
	rjmp LOOP_HASH

	rcall add_INIT	;; Compute intermediate hash value

	rcall restoreRegs	;; retrieve necessary AVR-GCC registers (r2-r17, r28-r29)

	ret			;; function return
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

CalculateT:
	rcall 	rotA
	rcall 	adde
	rcall	addk
	rcall	addWt
	rcall 	addf
	ret

rotA:
	lds		YH,	pA0+1 	;; A0 ptr
	lds 	YL,	pA0

	ldd		r16, Y+3
	ldd		r17, Y+2
	ldd		r18, Y+1
	ldd		r19, Y+0

	ldi 	r21, 0x5
loopROTL5:
	lsl		r16
	rOL		r17
	rOL		r18
	rOL		r19
	brcc	NOTC3
	ori		r16, 0x01
NOTC3:
	dec		r21
	brne	loopROTL5
	ret

adde:
	lds		YH,	pE0+1 	;; E0 ptr
	lds 	YL,	pE0

	ldd		r21, Y+3
	ldd		r22, Y+2
	ldd		r23, Y+1
	ldd		r24, Y+0

	add		r16, r21
	adc		r17, r22
	adc		r18, r23
	adc		r19, r24
	ret

addk:
	mov		r21, r20
	cpi		r21, 20
	brlo	ruleK1
	cpi		r21, 40
	brlo	ruleK2
	cpi		r21, 60
	brlo	ruleK3
	cpi		r21, 80
	brlo	ruleK4

ruleK1:
	ldi		r21, 0x99
	ldi		r22, 0x79
	ldi		r23, 0x82
	ldi		r24, 0x5A
	rjmp	FinishK

ruleK2:
	ldi		r21, 0xA1
	ldi		r22, 0xEB
	ldi		r23, 0xD9
	ldi		r24, 0x6E
	rjmp	FinishK

ruleK3:
	ldi		r21, 0xdc
	ldi		r22, 0xbc
	ldi		r23, 0x1b
	ldi		r24, 0x8f
	rjmp	FinishK

ruleK4:
	ldi		r21, 0xD6
	ldi		r22, 0xC1
	ldi		r23, 0x62
	ldi		r24, 0xCA
	rjmp	FinishK

FinishK:
	add		r16, r21
	adc		r17, r22
	adc		r18, r23
	adc		r19, r24
	ret

addWt:
	cpi		r20, 16
	brsh	Secondrule

	movw	YL, XL	;; Ws = Wt for t=0 until t=15

	ldd		r21, Y+3
	ldd		r22, Y+2
	ldd		r23, Y+1
	ldd		r24, Y+0

	add		r16, r21
	adc		r17, r22
	adc		r18, r23
	adc		r19, r24
	ret

Secondrule:				;; Ws = rOTL^1(Wt-3 .xor. Wt-8 .xor. Wt-14 .xor. Wt-18
	mov		r21, r20	;;; r20 = t (round / schedule counter)
	ldi		r22, 0x0F
	and		r21, r22
	lsl		r21			;; multiply by 4
	lsl		r21

	lds		YH,	pWt+1 	;; Wt ptr
	lds 	YL,	pWt
	add		YL, r21
	clr		r21
	adc		YH, r21
	push	YL
	push	YH

	ldd		r21, Y+3
	ldd		r22, Y+2
	ldd		r23, Y+1
	ldd		r24, Y+0

	push	XL			;;; preserve Wt ptr
	push	XH

	ldi		r26, 2*4
	clr		r27
	add		YL,	r26
	adc		YH,	r27

	pop		XH			;;; retrieve Wt ptr
	pop		XL

	rcall	UpdateY		;; don't overflow
;;;;;;;;;;;;;

	ldd		r6, Y+3
	ldd		r7, Y+2
	ldd		r8, Y+1
	ldd		r9, Y+0

	eor		r21, r6
	eor		r22, r7
	eor		r23, r8
	eor		r24, r9

	push	XL
	push	XH
	ldi		XL, 6*4
	clr		XH
	add		YL, XL
	adc		YH, XH
	pop		XH
	pop		XL

	rcall	UpdateY

	ldd		r6, Y+3
	ldd		r7, Y+2
	ldd		r8, Y+1
	ldd		r9, Y+0

	eor		r21, r6
	eor		r22, r7
	eor		r23, r8
	eor		r24, r9

	push	XL
	push	XH
	ldi		XL, 5*4
	clr		XH
	add		YL, XL
	adc		YH, XH
	pop		XH
	pop		XL

	rcall	UpdateY

	ldd		r6, Y+3
	ldd		r7, Y+2
	ldd		r8, Y+1
	ldd		r9, Y+0

	eor		r21, r6
	eor		r22, r7
	eor		r23, r8
	eor		r24, r9

	lsl		r21
	rOL		r22
	rOL		r23
	rOL		r24
	brcc	NOTC4
	ori		r21, 0x01
NOTC4:

	pop		YH			;;; extend to 16 bits
	pop		YL			;; get Ws
	std		Y+0, r24
	std		Y+1, r23
	std		Y+2, r22
	std		Y+3, r21

	add		r16, r21
	adc		r17, r22
	adc		r18, r23
	adc		r19, r24
	ret

;;; check for end of message (Y >= ctx->buf + 64)
;;; if at end, subtract ctx->buf + 64, add ctx->buf

UpdateY:
	push	YH					;;; save Y ptr
	push	YL
	clr		YH
	ldi		YL,	64				;;; msg length constant

	lds		XH,	pWt+1 			;;; setup end of message ptr for comparison
	lds 	XL,	pWt
	add		XL,	YL				;;; add constant
	adc		XH,	YH

	pop		YL					;;; retrieve Y ptr
	pop		YH
	cp		YL, XL				;;; compare to end of msg
	cpc		YH, XH
	brsh	UpdateY1			;;; if Y >= Wt+64 (64 bytes done), adjust Y to msg start offset (why? how can this not be Wt?)
	rjmp	FinishY
UpdateY1:
	sub		YL, XL				;;; subtract end of message ptr
	sbc		YH, XH
	lds		XH,	pWt+1 			;;;
	lds 	XL,	pWt
	add		YL, XL				;;; add start of message ptr
	adc		YH, XH
FinishY:
	ret


addf:
	lds		YH,	pC0+1 	;; C0 ptr
	lds 	YL,	pC0

	ldd		r21, Y+3
	ldd		r22, Y+2
	ldd		r23, Y+1
	ldd		r24, Y+0

	lds		YH,	pB0+1 	;; B0 ptr
	lds 	YL,	pB0

	ldd		r15, Y+3
	ldd		r14, Y+2
	ldd		r13, Y+1
	ldd		r12, Y+0

	lds		YH,	pD0+1 	;; D0 ptr
	lds 	YL,	pD0

	ldd		r11, Y+3
	ldd		r10, Y+2
	ldd		r9, Y+1
	ldd		r8, Y+0

	cpi		r20, 20		;; for t=0 to 19
	brlo	ruleF1		;; Ch(b,c,d) = (b .and. c) .xor. (-b .and d)

	cpi		r20, 40		;; for t=20 to 39
	brlo	ruleF2		;; Parity(b,c,d) = b .xor. c .xor. d

	cpi		r20, 60		;; for t=40 to 59
	brlo	ruleF3		;; Maj(b,c,d) = (b .and c) .xor. (b .and. d) .xor. (c .and. d)

	cpi		r20, 80		;; for t=60 to 79
	brlo	ruleF2		;; Parity(b,c,d) = b .xor. c .xor. d

ruleF1:
	and		r21, r15
	and		r22, r14
	and		r23, r13
	and		r24, r12

	com		r15
	com		r14
	com		r13
	com		r12

	and		r15, r11
	and		r14, r10
	and		r13, r9
	and		r12, r8

	eor		r21, r15
	eor		r22, r14
	eor		r23, r13
	eor		r24, r12
	rjmp	FinishF

ruleF2:
	eor		r21, r15
	eor		r22, r14
	eor		r23, r13
	eor		r24, r12

	eor		r21, r11
	eor		r22, r10
	eor		r23, r9
	eor		r24, r8
	rjmp	FinishF

ruleF3:
	push	r21			;; save c
	push	r22
	push	r23
	push	r24

	and		r21, r15	;; c & b
	and		r22, r14
	and		r23, r13
	and		r24, r12

	and		r15, r11	;; b & d
	and		r14, r10
	and		r13, r9
	and		r12, r8

	eor		r21, r15	;; XX = (c & b) .xor. (b & d)
	eor		r22, r14
	eor		r23, r13
	eor		r24, r12

	pop		r12			;; get c
	pop		r13
	pop		r14
	pop		r15

	and		r12, r8		;; c & d
	and		r13, r9
	and		r14, r10
	and		r15, r11

	eor		r21, r15	;; YY = XX .xor. (c & d)
	eor		r22, r14
	eor		r23, r13
	eor		r24, r12
	rjmp	FinishF

FinishF:
	add		r16, r21	;; addition modulo 2^W
	adc		r17, r22
	adc		r18, r23
	adc		r19, r24
	ret

Update:
	lds		YH,	pE0+1 	;; E0 ptr
	lds 	YL,	pE0
	lds		ZH,	pD0+1 	;; D0 ptr
	lds 	ZL,	pD0

	rcall GoTransfer	;; Y <-- Z
						;; e <-- d

	lds		YH,	pD0+1 	;; D0 ptr
	lds 	YL,	pD0
	lds		ZH,	pC0+1 	;; C0 ptr
	lds 	ZL,	pC0

	rcall GoTransfer	;; d <-- c

	lds		YH,	pB0+1 	;; B0 ptr
	lds 	YL,	pB0
	lds		ZH,	pA0+1 	;; A0 ptr
	lds 	ZL,	pA0

	rcall GoTransfer	;; b <-- a

	lds		YH,	pC0+1 	;; C0 ptr
	lds 	YL,	pC0

	st		Y+, r5			;; save c from r2-r5
	st		Y+, r4			;; c = rOTL^30(b)
	st  	Y+, r3
	st  	Y+, r2

	lds		YH,	pA0+1 		;; a = T
	lds 	YL,	pA0

	st		Y+, r19
	st		Y+, r18
	st		Y+, r17
	st		Y+, r16
	ret

GoTransfer:
	ldd	r21, Z+0
	std	Y+0, r21

	ldd	r21, Z+1
	std	Y+1, r21

	ldd	r21, Z+2
	std	Y+2, r21

	ldd	r21, Z+3
	std	Y+3, r21

	ret

add_INIT:	;; compute i intermediate hash value Hi
	lds	YH,	pA0+1 				;; A0 ptr
	lds	YL,	pA0
	ldi ZH, hi8(initAstore)		;; initial A value
	ldi ZL, lo8(initAstore)

	rcall Load4ByteY		;;; operand 1
	rcall Load4ByteZ		;;; operand 2
	rcall add4Byte
	rcall store4Byte

	lds	YH,	pB0+1 				;; B0 ptr
	lds	YL,	pB0
	ldi ZH, hi8(initBstore)		;; initial B value
	ldi ZL, lo8(initBstore)

	rcall Load4ByteY		;;; operand 1
	rcall Load4ByteZ		;;; operand 2
	rcall add4Byte
	rcall store4Byte

	lds	YH,	pC0+1 				;; C0 ptr
	lds	YL,	pC0
	ldi ZH, hi8(initCstore)		;; initial C value
	ldi ZL, lo8(initCstore)

	rcall Load4ByteY		;;; operand 1
	rcall Load4ByteZ		;;; operand 2
	rcall add4Byte
	rcall store4Byte

	lds	YH,	pD0+1 				;; D0 ptr
	lds	YL,	pD0
	ldi ZH, hi8(initDstore)		;; initial D value
	ldi ZL, lo8(initDstore)

	rcall Load4ByteY		;;; operand 1
	rcall Load4ByteZ		;;; operand 2
	rcall add4Byte
	rcall store4Byte

	lds	YH,	pE0+1 				;; E0 ptr
	lds	YL,	pE0
	ldi ZH, hi8(initEstore)		;; initial E value
	ldi ZL, lo8(initEstore)

	rcall Load4ByteY		;;; operand 1
	rcall Load4ByteZ		;;; operand 2
	rcall add4Byte
	rcall store4Byte
	ret

Load4ByteY:
	ldd r16, Y+0
	ldd r17, Y+1
	ldd r18, Y+2
	ldd r19, Y+3
	ret

Load4ByteZ:
	ldd	r21, Z+0		;;; initial H values
	ldd	r22, Z+1
	ldd	r23, Z+2
	ldd	r24, Z+3
	ret

store4Byte:
	std Y+0, r16
	std Y+1, r17
	std Y+2, r18
	std Y+3, r19
	ret

add4Byte:
	add r19, r24
	adc r18, r23
	adc r17, r22
	adc r16, r21
	ret

;; save necessary AVR-GCC registers (r2-r17, r28-r29)
saveRegs:
	pop r0	;; save return address, these regs aren't saved
	pop r1

	push r2
	push r3
	push r4
	push r5
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push r16
	push r17
	push r28
	push r29

	push r1	;; restore return address
	push r0
	ret

;; restore necessary AVR-GCC registers (r2-r17, r28-r29)
restoreRegs:
	pop r0	;; grab return address, these regs aren't saved
	pop r1

	pop r29
	pop r28
	pop r17
	pop r16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r4
	pop r5
	pop r2
	pop r3

	push r1	;; restore return address
	push r0
	clr	r1	;; assumed to be 0 by GCC
	ret

; these vars hold the current addresses of the chaining variables and message ptrs
initVarPtrs:
	movw XL,r22		;; get ctx->h ptr to X
	sts pA0+1, XH	;; A0 ptr
	sts pA0, XL
	adiw XL,4
	sts pB0+1, XH	;; B0 ptr
	sts pB0, XL
	adiw XL,4
	sts pC0+1, XH	;; C0 ptr
	sts pC0, XL
	adiw XL,4
	sts pD0+1, XH	;; D0 ptr
	sts pD0, XL
	adiw XL,4
	sts pE0+1, XH	;; E0 ptr
	sts pE0, XL

	movw XL,r24		;; get ctx->buf (msg) ptr to X (Wt)
	sts pWt+1, XH	;; Wt ptr
	sts pWt, XL

	ret

saveInitVars:

	lds		YH,	pA0+1 				;; A0 ptr
	lds 	YL,	pA0
	rcall	Load4ByteY				;;; get A values
	ldi		YH,	hi8(initAstore) 	;; initial A value
	ldi 	YL,	lo8(initAstore)
	rcall	store4Byte				;;; save A values

	lds		YH,	pB0+1 				;; B0 ptr
	lds 	YL,	pB0
	rcall	Load4ByteY				;;; get B values
	ldi		YH,	hi8(initBstore) 	;; initial B value
	ldi 	YL,	lo8(initBstore)
	rcall	store4Byte				;;; save B values

	lds		YH,	pC0+1 				;; C0 ptr
	lds 	YL,	pC0
	rcall	Load4ByteY				;;; get C values
	ldi		YH,	hi8(initCstore) 	;; initial C value
	ldi 	YL,	lo8(initCstore)
	rcall	store4Byte				;;; save C values

	lds		YH,	pD0+1 				;; D0 ptr
	lds 	YL,	pD0
	rcall	Load4ByteY				;;; get D values
	ldi		YH,	hi8(initDstore) 	;; initial D value
	ldi 	YL,	lo8(initDstore)
	rcall	store4Byte				;;; save A values

	lds		YH,	pE0+1 				;; E0 ptr
	lds 	YL,	pE0
	rcall	Load4ByteY				;;; get E values
	ldi		YH,	hi8(initEstore) 	;; initial E value
	ldi 	YL,	lo8(initEstore)
	rcall	store4Byte				;;; save E values

	ret
