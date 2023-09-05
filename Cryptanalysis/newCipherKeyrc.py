```
@authors: Anushka Sivakumar, Asmi Sriwastawa
```

# key recovery cryptosmt

# from parser import stpcommands
# from ciphers.cipher import AbstractCipher

# from parser.stpcommands import getStringLeftRotate as rotl
# from parser.stpcommands import getStringRightRotate as rotr

from random import seed
from random import randint
seed(1)


class NewCipherKeyRc(AbstractCipher):
	name = "newcipherkeyrc"
	rot_alpha = 7
	rot_beta = 1
	rot_gamma = 2
	num_messages = 1

	def getFormatString(self):
		format_string = []
		messages_print = (min(4, self.num_messages))
		for msg in range(messages_print):
			format_string.append('l0{}r'.format(msg))
			format_string.append('l1{}r'.format(msg))
			format_string.append('r0{}r'.format(msg))
			format_string.append('r1{}r'.format(msg))
		format_string += ['dl01r', 'dl11r', 'dr01r', 'dr11r', 'key0', 'key1', 'key2', 'key3', 'key4', 'key5', 'key6', 'key7']
		return format_string

	def createSTP(self, stp_filename, parameters):
		wordsize = parameters["wordsize"]
		rounds = parameters["rounds"]
		weight = parameters["sweight"]
		
		if "rotationconstants" in parameters:
			self.rot_alpha = parameters["rotationconstants"][0]
			self.rot_beta = parameters["rotationconstants"][1]
			self.rot_gamma = parameters["rotationconstants"][2]
		
		self.num_messages = parameters["nummessages"]
		
		with open(stp_filename, 'w') as stp_file:
			header = ("% Input File for STP\n% NewCipher w={} alpha={} beta={}"
				  " gamma={} rounds={}\n\n\n".format(wordsize,self.rot_alpha,self.rot_beta,self.rot_gamma,rounds))
			
			stp_file.write(header)
			
			key0 = ["key0{}".format(i) for i in range(int(rounds/4) + 1)]
			key1 = ["key1{}".format(i) for i in range(int(rounds/4) + 1)]
			key2 = ["key2{}".format(i) for i in range(int(rounds/4) + 1)]
			key3 = ["key3{}".format(i) for i in range(int(rounds/4) + 1)]
			key4 = ["key4{}".format(i) for i in range(int(rounds/4) + 1)]
			key5 = ["key5{}".format(i) for i in range(int(rounds/4) + 1)]
			key6 = ["key6{}".format(i) for i in range(int(rounds/4) + 1)]
			key7 = ["key7{}".format(i) for i in range(int(rounds/4) + 1)]
			
			stpcommands.setupVariables(stp_file, key0, wordsize)
			stpcommands.setupVariables(stp_file, key1, wordsize)
			stpcommands.setupVariables(stp_file, key2, wordsize)
			stpcommands.setupVariables(stp_file, key3, wordsize)
			stpcommands.setupVariables(stp_file, key4, wordsize)
			stpcommands.setupVariables(stp_file, key5, wordsize)
			stpcommands.setupVariables(stp_file, key6, wordsize)
			stpcommands.setupVariables(stp_file, key7, wordsize)
	 
			self.setupKeySchedule(stp_file, key0, key1, key2, key3, key4, key5, key6, key7, wordsize, rounds)
			
			for msg in range(self.num_messages):
				l0 = ["l0{}r{}".format(msg, i) for i in range(rounds + 1)]
				l1 = ["l1{}r{}".format(msg, i) for i in range(rounds + 1)]
				r0 = ["r0{}r{}".format(msg, i) for i in range(rounds + 1)]
				r1 = ["r1{}r{}".format(msg, i) for i in range(rounds + 1)]
				and_out0 = ["andout0{}r{}".format(msg, i) for i in range(rounds + 1)]
				and_out1 = ["andout1{}r{}".format(msg, i) for i in range(rounds + 1)]
				stpcommands.setupVariables(stp_file, l0, wordsize)
				stpcommands.setupVariables(stp_file, l1, wordsize)
				stpcommands.setupVariables(stp_file, r0, wordsize)
				stpcommands.setupVariables(stp_file, r1, wordsize)
				stpcommands.setupVariables(stp_file, and_out0, wordsize)
				stpcommands.setupVariables(stp_file, and_out1, wordsize)
				
				for i in range(rounds):
					j = int(i/4)
					self.setupNewCipherRound(stp_file, i, l0[i], l1[i], r0[i], r1[i], l0[i+1], l1[i+1], r0[i+1], r1[i+1], and_out0[i], and_out1[i], key0[j], key1[j], key2[j], key3[j], key4[j], key5[j], key6[j], key7[j], wordsize, rounds)
			
			for msg in range(1, self.num_messages):
				delta_l0 = ["dl0{}r{}".format(msg, i) for i in range(rounds + 1)]
				delta_l1 = ["dl1{}r{}".format(msg, i) for i in range(rounds + 1)]
				delta_r0 = ["dr0{}r{}".format(msg, i) for i in range(rounds + 1)]
				delta_r1 = ["dr1{}r{}".format(msg, i) for i in range(rounds + 1)]
				stpcommands.setupVariables(stp_file, delta_l0, wordsize)
				stpcommands.setupVariables(stp_file, delta_l1, wordsize)
				stpcommands.setupVariables(stp_file, delta_r0, wordsize)
				stpcommands.setupVariables(stp_file, delta_r1, wordsize)
				for i in range(rounds + 1):
					stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_l0[i], "l00r{}".format(i),"l0{}r{}".format(msg, i)))
					stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_l1[i], "l10r{}".format(i),"l1{}r{}".format(msg, i)))
					stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_r0[i], "r00r{}".format(i),"r0{}r{}".format(msg, i)))
					stp_file.write("ASSERT({} = BVXOR({}, {}));\n".format(delta_r1[i], "r10r{}".format(i),"r1{}r{}".format(msg, i)))
			
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
	
	def setupNewCipherRound(self, stp_file, rnd, l0_in, l1_in, r0_in, r1_in, l0_out, l1_out, r0_out, r1_out, and_out0, and_out1, key0, key1, key2, key3, key4, key5, key6, key7, wordsize, rounds):
		command = ""
		
		if rnd%4 == 0:
			command += "ASSERT({} = {});\n".format(l1_out, l0_in)
			command += "ASSERT({} = {});\n".format(r1_out, r0_in)
			command += "ASSERT({} = {} & {});\n".format(and_out0,rotl(l0_in, self.rot_beta, wordsize),rotl(l0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = {} & {});\n".format(and_out1,rotl(r0_in, self.rot_beta, wordsize),rotl(r0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(l0_out, key0, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(r0_out, key2, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		elif rnd == rounds-1:
			command += "ASSERT({} = {});\n".format(l0_out, l0_in)
			command += "ASSERT({} = {});\n".format(r0_out, r0_in)
			command += "ASSERT({} = {} & {});\n".format(and_out0,rotl(l0_in, self.rot_beta, wordsize),rotl(l0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = {} & {});\n".format(and_out1,rotl(r0_in, self.rot_beta, wordsize),rotl(r0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(l1_out, key5, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(r1_out, key7, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		elif (rnd-1)%4 == 0:
			command += "ASSERT({} = {});\n".format(r0_out, l0_in)
			command += "ASSERT({} = {});\n".format(l0_out, r0_in)
			command += "ASSERT({} = {} & {});\n".format(and_out0,rotl(l0_in, self.rot_beta, wordsize),rotl(l0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = {} & {});\n".format(and_out1,rotl(r0_in, self.rot_beta, wordsize),rotl(r0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(l1_out, key4, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(r1_out, key6, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		elif (rnd-2)%4 == 0:
			command += "ASSERT({} = {});\n".format(l1_out, l0_in)
			command += "ASSERT({} = {});\n".format(r1_out, r0_in)
			command += "ASSERT({} = {} & {});\n".format(and_out0,rotl(l0_in, self.rot_beta, wordsize),rotl(l0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = {} & {});\n".format(and_out1,rotl(r0_in, self.rot_beta, wordsize),rotl(r0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(l0_out, key1, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(r0_out, key3, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		elif (rnd-3)%4 == 0:
			command += "ASSERT({} = {});\n".format(r0_out, l0_in)
			command += "ASSERT({} = {});\n".format(l0_out, r0_in)
			command += "ASSERT({} = {} & {});\n".format(and_out0,rotl(l0_in, self.rot_beta, wordsize),rotl(l0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = {} & {});\n".format(and_out1,rotl(r0_in, self.rot_beta, wordsize),rotl(r0_in, self.rot_alpha, wordsize))
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(l1_out, key5, rotl(l0_in, self.rot_gamma, wordsize), and_out0, l1_in)
			command += "ASSERT({} = BVXOR({}, BVXOR({}, BVXOR({}, {}))));\n".format(r1_out, key7, rotl(r0_in, self.rot_gamma, wordsize), and_out1, r1_in)
		
		stp_file.write(command)
		return