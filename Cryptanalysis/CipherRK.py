```
@author: Anushka Sivakumar, Asmi Sriwastawa
```


# differential cryptanalysis
from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl
from parser.stpcommands import getStringRightRotate as rotr

from random import seed
from random import randint
seed(1)

class NewCipherRK(AbstractCipher):
	name = "newcipherrk"
	rot_alpha = 7
	rot_beta = 1
	rot_gamma = 2

	def getFormatString(self):
		format_string = ['l0', 'l1', 'r0', 'r1', 
		                 'key0', 'key1', 'key2', 'key3', 'key4', 'key5', 'key6', 'key7',
										         'w0', 'w1', 'weight']
		return format_string

	def createSTP(self, stp_filename, parameters):
		wordsize = parameters["wordsize"]
		rounds = parameters["rounds"]
		weight = parameters["sweight"]
		
		if "rotationconstants" in parameters:
			self.rot_alpha = parameters["rotationconstants"][0]
			self.rot_beta = parameters["rotationconstants"][1]
			self.rot_gamma = parameters["rotationconstants"][2]
		
		
		with open(stp_filename, 'w') as stp_file:
			header = ("% Input File for STP\n% NewCipher w={} alpha={} beta={} gamma={} rounds={}\n\n\n".format(wordsize,self.rot_alpha,self.rot_beta,self.rot_gamma,rounds))
			
			stp_file.write(header)
			# Setup variables
			# state = l0, l1, r0, r1
			# intermediate values = a0, a1, a2, a3
			l0 = ["l0{}".format(i) for i in range(rounds + 1)]
			l1 = ["l1{}".format(i) for i in range(rounds + 1)]
			r0 = ["r0{}".format(i) for i in range(rounds + 1)]
			r1 = ["r1{}".format(i) for i in range(rounds + 1)]
			
			# for key
			key0 = ["key0{}".format(i) for i in range(int(rounds/4) + 1)]
			key1 = ["key1{}".format(i) for i in range(int(rounds/4) + 1)]
			key2 = ["key2{}".format(i) for i in range(int(rounds/4) + 1)]
			key3 = ["key3{}".format(i) for i in range(int(rounds/4) + 1)]
			key4 = ["key4{}".format(i) for i in range(int(rounds/4) + 1)]
			key5 = ["key5{}".format(i) for i in range(int(rounds/4) + 1)]
			key6 = ["key6{}".format(i) for i in range(int(rounds/4) + 1)]
			key7 = ["key7{}".format(i) for i in range(int(rounds/4) + 1)]
			
			# for and
			and_out0 = ["andout0{}".format(i) for i in range(rounds + 1)]
			and_out1 = ["andout1{}".format(i) for i in range(rounds + 1)]

			# w = weight of each modular addition
			w0 = ["w0{}".format(i) for i in range(rounds)]
			w1 = ["w1{}".format(i) for i in range(rounds)]

			stpcommands.setupVariables(stp_file, l0, wordsize)
			stpcommands.setupVariables(stp_file, l1, wordsize)
			stpcommands.setupVariables(stp_file, r0, wordsize)
			stpcommands.setupVariables(stp_file, r1, wordsize)
			stpcommands.setupVariables(stp_file, key0, wordsize)
			stpcommands.setupVariables(stp_file, key1, wordsize)
			stpcommands.setupVariables(stp_file, key2, wordsize)
			stpcommands.setupVariables(stp_file, key3, wordsize)
			stpcommands.setupVariables(stp_file, key4, wordsize)
			stpcommands.setupVariables(stp_file, key5, wordsize)
			stpcommands.setupVariables(stp_file, key6, wordsize)
			stpcommands.setupVariables(stp_file, key7, wordsize)
			stpcommands.setupVariables(stp_file, and_out0, wordsize)
			stpcommands.setupVariables(stp_file, and_out1, wordsize)
			stpcommands.setupVariables(stp_file, w0, wordsize)
			stpcommands.setupVariables(stp_file, w1, wordsize)
	 
			stpcommands.setupWeightComputation(stp_file, weight, w0 + w1, wordsize)
			
			#key-schedule
			self.setupKeySchedule(stp_file, key0, key1, key2, key3, key4, key5, key6, key7, wordsize, rounds)
				
			for i in range(rounds):
				j = int(i/4)
				self.setupNewCipherRound(stp_file, i, l0[i], l1[i], r0[i], r1[i], l0[i+1], l1[i+1], r0[i+1], r1[i+1], 
				                         and_out0[i], and_out1[i], key0[j], key1[j], key2[j], key3[j], key4[j], key5[j], key6[j], key7[j],
																             w0[i], w1[i], wordsize, rounds)
				
			# No all zero characteristic
			stpcommands.assertNonZero(stp_file, l0+l1+r0+r1, wordsize)
			
			# Iterative characteristics only
			# Input difference = Output difference
			if parameters["iterative"]:
				stpcommands.assertVariableValue(stp_file, l0[0], l0[rounds])
				stpcommands.assertVariableValue(stp_file, r0[0], r0[rounds])
				stpcommands.assertVariableValue(stp_file, l1[0], l1[rounds])
				stpcommands.assertVariableValue(stp_file, r1[0], r1[rounds])
			
			for key, value in parameters["fixedVariables"].items():
				stpcommands.assertVariableValue(stp_file, key, value)
			
			for char in parameters["blockedCharacteristics"]:
				stpcommands.blockCharacteristic(stp_file, char, wordsize)
			
			stpcommands.setupQuery(stp_file)
		return


	def setupKeySchedule(self, stp_file, key0, key1, key2, key3, key4, key5, key6, key7, wordsize, rounds):
		command = ""
		
		if rounds > 4:
			for i in range(1, int(rounds/4) + 1):
				command += "ASSERT({} = {});\n".format(key0[i], rotl(key0[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key1[i], rotl(key1[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key2[i], rotl(key2[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key3[i], rotl(key3[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key4[i], rotl(key4[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key5[i], rotl(key5[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key6[i], rotl(key6[i-1], 1, wordsize))
				command += "ASSERT({} = {});\n".format(key7[i], rotl(key7[i-1], 1, wordsize))
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key0[i], key0[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key1[i], key1[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key2[i], key2[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key3[i], key3[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key4[i], key4[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key5[i], key5[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key6[i], key6[i], "0x0087")
				rand = randint(0, 1)
				if rand == 1:
					command += "ASSERT({} = BVXOR({}, {}));\n".format(key7[i], key7[i], "0x0087")
		
		stp_file.write(command)
		return

	def getDoubleBits(self, x_in, wordsize):
		command = "({0} & ~{1} & {2})".format(
			rotl(x_in, self.rot_beta, wordsize),
			rotl(x_in, self.rot_alpha, wordsize),
			rotl(x_in, 2 * self.rot_alpha - self.rot_beta, wordsize))
		return command

	def setupNewCipherRound(self, stp_file, rnd, l0_in, l1_in, r0_in, r1_in, l0_out, l1_out, r0_out, r1_out, 
	                      and_out0, and_out1, key0, key1, key2, key3, key4, key5, key6, key7, 
												           w0, w1, wordsize, rounds):
		"""
		Model for differential behaviour of half round
 
		uint16_t state0 = (rotate_left(l0,1,16)&rotate_left(l0,7,16))^(l1)^(rotate_left(l0,2,16))^round_key[1];
		uint16_t state1 = (rotate_left(r0,1,16)&rotate_left(r0,7,16))^(r1)^(rotate_left(r0,2,16))^round_key[3];

		alpha = 7, beta = 1, gamma = 2
		
		"""
		command = ""

		# ------ LHS
		#Assert(l0_in <<< self.rot_alpha & l0_in <<< self.rot.beta + l1_in + l0_in <<< self.rotgamma = s0 = l0_out)
		if rnd % 2 == 0:
			#l1_out = l1_in
			command += "ASSERT ({}={});\n".format(l1_out, l0_in)
		else:
			# if last round
			if rnd == rounds-1:
				command += "ASSERT ({}={});\n".format(l0_out, l0_in)
			else:
				# l0_out = r0_in
				command += "ASSERT ({}={});\n".format(l0_out, r0_in)
		
		# weight computation for LHS
		l0_in_rotalpha = rotl(l0_in, self.rot_alpha, wordsize)
		l0_in_rotbeta = rotl(l0_in, self.rot_beta, wordsize)

		# Deal with dependent inputs
		varibits = "({0} | {1})".format(l0_in_rotalpha, l0_in_rotbeta)
		doublebits = self.getDoubleBits(l0_in, wordsize)

		#Check for valid difference
		firstcheck = "({} & ~{})".format(and_out0, varibits)
		secondcheck = "(BVXOR({}, {}) & {})".format(
				and_out0, rotl(and_out0, self.rot_alpha - self.rot_beta, wordsize), doublebits)
		thirdcheck = "(IF {0} = 0x{1} THEN BVMOD({2}, {3}, 0x{4}2) ELSE 0x{5} ENDIF)".format(
				l0_in, "f" * (wordsize // 4), wordsize, and_out0, "0" * (wordsize // 4 - 1),
				"0" * (wordsize // 4))

		command += "ASSERT(({} | {} | {}) = 0x{});\n".format(
				firstcheck, secondcheck, thirdcheck, "0" * (wordsize // 4))
		
	 
		if rnd%2 == 0:  # lhs half round 1
			if rnd%4 == 0: # ()
				key0l = key0
			else:
				key0l = key1
			#Rest of XOR
			command += "ASSERT({} = {} & {});\n".format(and_out0, 
															rotl(l0_in, self.rot_alpha, wordsize), 
															rotl(l0_in, self.rot_beta, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {})));\n".format(
					key0l, l0_out, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
		else: # lhs half round 2
			if (rnd+1)%4 == 0:
				key1l = key5
			else:
				key1l = key4
			# Rest XOR 
			command += "ASSERT({} = {} & {});\n".format(and_out1, 
															rotl(l0_in, self.rot_alpha, wordsize), 
															rotl(l0_in, self.rot_beta, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {})));\n".format(
					key1l, l1_out, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
		
			
		#Weight computation
		command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
						ELSE BVXOR({2}, {3}) ENDIF));\n".format(
						w0, l0_in, varibits, doublebits, "f" * (wordsize // 4),
						wordsize, "0"*((wordsize // 4) - 1))
						
		# ------ RHS
		
		#Assert(r0_in <<< self.rot_alpha & r0_in <<< self.rot.beta + r1_in + r0_in <<< self.rotgamma = s1 = r0_out)
		
		if rnd%2 == 0:
			# r1_out = r1_in
			command += "ASSERT ({}={});\n".format(r1_out, r0_in)	
		else:
				# if last round
				if rnd == rounds-1:
					command += "ASSERT ({}={});\n".format(r0_out, r0_in)
				else:
					# r0_out = l0_in
					command += "ASSERT ({}={});\n".format(r0_out, l0_in)

		# weight computation for RHS
		
		r0_in_rotalpha = rotl(r0_in, self.rot_alpha, wordsize)
		r0_in_rotbeta = rotl(r0_in, self.rot_beta, wordsize)

		#Deal with dependent inputs
		varibits = "({0} | {1})".format(r0_in_rotalpha, r0_in_rotbeta)
		doublebits = self.getDoubleBits(r0_in, wordsize)

		#Check for valid difference
		firstcheck = "({} & ~{})".format(and_out1, varibits)
		secondcheck = "(BVXOR({}, {}) & {})".format(
				and_out1, rotl(and_out1, self.rot_alpha - self.rot_beta, wordsize), doublebits)
		thirdcheck = "(IF {0} = 0x{1} THEN BVMOD({2}, {3}, 0x{4}2) ELSE 0x{5} ENDIF)".format(
				r0_in, "f" * (wordsize // 4), wordsize, and_out1, "0" * (wordsize // 4 - 1),
				"0" * (wordsize // 4))

		command += "ASSERT(({} | {} | {}) = 0x{});\n".format(
				firstcheck, secondcheck, thirdcheck, "0" * (wordsize // 4))
		
		if rnd%2 == 0:
			if rnd%4 == 0:
				key0r = key2
			else:
				key0r = key3
			# Rest XOR 
			command += "ASSERT({} = {} & {});\n".format(and_out1, 
															rotl(r0_in, self.rot_alpha, wordsize), 
															rotl(r0_in, self.rot_beta, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {})));\n".format(
					key0r, r0_out, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		else:
			if (rnd+1)%4 == 0:
				key1r = key7
			else:
				key1r = key6
			# Rest XOR 
			command += "ASSERT({} = {} & {});\n".format(and_out1, 
															rotl(r0_in, self.rot_alpha, wordsize), 
															rotl(r0_in, self.rot_beta, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {})));\n".format(
					key1r, r1_out, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		
		#Weight computation
		command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
						ELSE BVXOR({2}, {3}) ENDIF));\n".format(
						w1, r0_in, varibits, doublebits, "f" * (wordsize // 4),
						wordsize, "0"*((wordsize // 4) - 1))	

		stp_file.write(command)
		return