def get_lowest_bits(n, number_of_bits):
	"""Returns the lowest "number_of_bits" bits of n."""
	mask = (1 << number_of_bits) - 1
	return n & mask

class MT19937:
    def init_state_32_bits(self):
        self.W, self.N, self.M, self.R = 32, 624, 397, 31
        self.A = 0x9908B0DF
        self.U, self.D = 11, 0xFFFFFFFF
        self.S, self.B = 7, 0x9D2C5680
        self.T, self.C = 15, 0xEFC60000
        self.L = 18
        self.F = 1812433253

    def init_state_64_bits(self):
        self.W, self.N, self.M, self.R = 64, 312, 156, 31
        self.A = 0xB5026F5AA96619E9
        self.U, self.D = 29, 0x5555555555555555
        self.S, self.B = 17, 0x71D67FFFEDA60000
        self.T, self.C = 37, 0xFFF7EEE000000000
        self.L = 43
        self.F = 6364136223846793005

    def __init__(self, seed, _32bits=True ):
        self.mt = []
        self._32bits = _32bits
        self.init_state_32_bits() if _32bits else self.init_state_64_bits()

        self.LOWER_MASK = (1 << self.R) - 1
        self.UPPER_MASK = get_lowest_bits(~ self.LOWER_MASK, self.W)

        self.index = self.N
        self.mt.append(seed)
        for i in range(1, self.index):
            self.mt.append(get_lowest_bits(self.F * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.W - 2))) + i, self.W))

    def extract_number(self):
        if self.index >= self.N:## vuln this
            self.twist()

        y = self.mt[self.index]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= (y >> self.L)

        self.index += 1
        return get_lowest_bits(y, self.W)

    def twist(self):## Exist 2 diff mt => indentical result
        for i in range(self.N):
            x = (self.mt[i] & self.UPPER_MASK) | (self.mt[(i + 1) % self.N] & self.LOWER_MASK)
            x_a = x >> 1
            if x % 2 != 0:x_a ^= self.A
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ x_a
        self.index = 0

class ReverseOutput:
	def __init__(self,clone_prng,_32bits=True):
		self.bits = 32 if _32bits else 64
		self.clone_prng = clone_prng
	
	def get_bit(self, number, position):
		return 0 if position < 0 or position > (self.bits-1) else (number >> ((self.bits-1) - position)) & 1
	
	def set_bit_to_one(self, number, position):
		return number | (1 << ((self.bits-1) - position))
			
	def undo_right_shift_xor(self, result, shift_len):
		original = 0
		for i in range(self.bits):
			next_bit = self.get_bit(result, i) ^ self.get_bit(original, i - shift_len)
			if next_bit == 1:original = self.set_bit_to_one(original, i)
		return original
	
	def undo_left_shift_xor_and(self, result, shift_len, andd):
		original = 0
		for i in range(self.bits):
			next_bit = self.get_bit(result, (self.bits-1) - i) ^ (self.get_bit(original, (self.bits-1) - (i - shift_len)) & self.get_bit(andd, (self.bits-1) - i))
			if next_bit == 1: original = self.set_bit_to_one(original, (self.bits-1) - i)
		return original

	def undo_right_shift_xor_and(self, result, shift_len, andd):
		original = 0
		for i in range(self.bits):
			next_bit = self.get_bit(result, i) ^ (self.get_bit(original,(i - shift_len)) & self.get_bit(andd, i))
			if next_bit == 1: original = self.set_bit_to_one(original, i)
		return original
	
	def untemper(self,y):
		y = self.undo_right_shift_xor(y, self.clone_prng.L)
		y = self.undo_left_shift_xor_and(y, self.clone_prng.T, self.clone_prng.C)
		y = self.undo_left_shift_xor_and(y, self.clone_prng.S, self.clone_prng.B)
		y = self.undo_right_shift_xor_and(y, self.clone_prng.U,self.clone_prng.D)
		return y

if __name__=='__main__':
	print("TEST")