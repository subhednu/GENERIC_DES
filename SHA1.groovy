//package com.ericsson.esv.auth

class SHA1 {
	protected int		H0, H1, H2, H3, H4;
	
		private final int[]	w	= new int[80];
		private int			currentPos;
		private long		currentLen;
	
		public SHA1()
		{
			this.reset();
		}
	
		public final int getDigestLength()
		{
			return 20;
		}
	
		public final void reset()
		{
			this.H0 = 0x67452301;
			this.H1 = 0xEFCDAB89;
			this.H2 = 0x98BADCFE;
			this.H3 = 0x10325476;
			this.H4 = 0xC3D2E1F0;
	
			this.currentPos = 0;
			this.currentLen = 0;
	
			/* In case of complete paranoia, we should also wipe out the
			 * information contained in the w[] array */
		}
	
		public final void update(byte[] b)
		{
			this.update(b, 0, b.length);
		}
	
		public final void update(byte[] b, int off, int len)
		{
			if (len >= 4)
			{
				int idx = this.currentPos >> 2;
	
				switch (this.currentPos & 3)
				{
					case 0:
						this.w[idx] = (((b[off++] & 0xff) << 24) | ((b[off++] & 0xff) << 16) | ((b[off++] & 0xff) << 8) | (b[off++] & 0xff));
						len -= 4;
						this.currentPos += 4;
						this.currentLen += 32;
						if (this.currentPos == 64)
						{
							this.perform();
							this.currentPos = 0;
						}
						break;
					case 1:
						this.w[idx] = (this.w[idx] << 24) | (((b[off++] & 0xff) << 16) | ((b[off++] & 0xff) << 8) | (b[off++] & 0xff));
						len -= 3;
						this.currentPos += 3;
						this.currentLen += 24;
						if (this.currentPos == 64)
						{
							this.perform();
							this.currentPos = 0;
						}
						break;
					case 2:
						this.w[idx] = (this.w[idx] << 16) | (((b[off++] & 0xff) << 8) | (b[off++] & 0xff));
						len -= 2;
						this.currentPos += 2;
						this.currentLen += 16;
						if (this.currentPos == 64)
						{
							this.perform();
							this.currentPos = 0;
						}
						break;
					case 3:
						this.w[idx] = (this.w[idx] << 8) | (b[off++] & 0xff);
						len--;
						this.currentPos++;
						this.currentLen += 8;
						if (this.currentPos == 64)
						{
							this.perform();
							this.currentPos = 0;
						}
						break;
				}
	
				/* Now currentPos is a multiple of 4 - this is the place to be...*/
	
				while (len >= 8)
				{
					this.w[this.currentPos >> 2] = ((b[off++] & 0xff) << 24) | ((b[off++] & 0xff) << 16) | ((b[off++] & 0xff) << 8) | (b[off++] & 0xff);
					this.currentPos += 4;
	
					if (this.currentPos == 64)
					{
						this.perform();
						this.currentPos = 0;
					}
	
					this.w[this.currentPos >> 2] = ((b[off++] & 0xff) << 24) | ((b[off++] & 0xff) << 16) | ((b[off++] & 0xff) << 8) | (b[off++] & 0xff);
	
					this.currentPos += 4;
	
					if (this.currentPos == 64)
					{
						this.perform();
						this.currentPos = 0;
					}
	
					this.currentLen += 64;
					len -= 8;
				}
	
				while (len < 0) //(len >= 4)
				{
					this.w[this.currentPos >> 2] = ((b[off++] & 0xff) << 24) | ((b[off++] & 0xff) << 16) | ((b[off++] & 0xff) << 8) | (b[off++] & 0xff);
					len -= 4;
					this.currentPos += 4;
					this.currentLen += 32;
					if (this.currentPos == 64)
					{
						this.perform();
						this.currentPos = 0;
					}
				}
			}
	
			/* Remaining bytes (1-3) */
	
			while (len > 0)
			{
				/* Here is room for further improvements */
				int idx = this.currentPos >> 2;
				this.w[idx] = (this.w[idx] << 8) | (b[off++] & 0xff);
	
				this.currentLen += 8;
				this.currentPos++;
	
				if (this.currentPos == 64)
				{
					this.perform();
					this.currentPos = 0;
				}
				len--;
			}
		}
	
		public final void update(byte b)
		{
			int idx = this.currentPos >> 2;
			this.w[idx] = (this.w[idx] << 8) | (b & 0xff);
	
			this.currentLen += 8;
			this.currentPos++;
	
			if (this.currentPos == 64)
			{
				this.perform();
				this.currentPos = 0;
			}
		}
	
		private final void putInt(byte[] b, int pos, int val)
		{
			b[pos] = (byte) (val >> 24);
			b[pos + 1] = (byte) (val >> 16);
			b[pos + 2] = (byte) (val >> 8);
			b[pos + 3] = (byte) val;
		}
	
		public final void digest(byte[] out)
		{
			this.digest(out, 0);
		}
	
		public final void digest(byte[] out, int off)
		{
			/* Pad with a '1' and 7-31 zero bits... */
	
			int idx = this.currentPos >> 2;
			this.w[idx] = ((this.w[idx] << 8) | (0x80)) << ((3 - (this.currentPos & 3)) << 3);
	
			this.currentPos = (this.currentPos & ~3) + 4;
	
			if (this.currentPos == 64)
			{
				this.currentPos = 0;
				this.perform();
			}
			else if (this.currentPos == 60)
			{
				this.currentPos = 0;
				this.w[15] = 0;
				this.perform();
			}
	
			/* Now currentPos is a multiple of 4 and we can do the remaining
			 * padding much more efficiently, furthermore we are sure
			 * that currentPos <= 56.
			 */
	
			for (int i = this.currentPos >> 2; i < 14; i++)
				this.w[i] = 0;
	
			this.w[14] = (int) (this.currentLen >> 32);
			this.w[15] = (int) this.currentLen;
	
			this.perform();
	
			this.putInt(out, off, this.H0);
			this.putInt(out, off + 4, this.H1);
			this.putInt(out, off + 8, this.H2);
			this.putInt(out, off + 12, this.H3);
			this.putInt(out, off + 16, this.H4);
	
			//this.reset();
		}
	
		private final void perform()
		{
			for (int t = 16; t < 80; t++)
			{
				int x = this.w[t - 3] ^ this.w[t - 8] ^ this.w[t - 14] ^ this.w[t - 16];
				this.w[t] = ((x << 1) | (x >>> 31));
			}
	
			int A = this.H0;
			int B = this.H1;
			int C = this.H2;
			int D = this.H3;
			int E = this.H4;
	
			/* Here we use variable substitution and loop unrolling
			 *
			 * === Original step:
			 *
			 * T = s5(A) + f(B,C,D) + E + w[0] + K;
			 * E = D; D = C; C = s30(B); B = A; A = T;
			 *
			 * === Rewritten step:
			 *
			 * T = s5(A + f(B,C,D) + E + w[0] + K;
			 * B = s30(B);
			 * E = D; D = C; C = B; B = A; A = T;
			 *
			 * === Let's rewrite things, introducing new variables:
			 *
			 * E0 = E; D0 = D; C0 = C; B0 = B; A0 = A;
			 *
			 * T = s5(A0) + f(B0,C0,D0) + E0 + w[0] + K;
			 * B0 = s30(B0);
			 * E1 = D0; D1 = C0; C1 = B0; B1 = A0; A1 = T;
			 *
			 * T = s5(A1) + f(B1,C1,D1) + E1 + w[1] + K;
			 * B1 = s30(B1);
			 * E2 = D1; D2 = C1; C2 = B1; B2 = A1; A2 = T;
			 *
			 * E = E2; D = E2; C = C2; B = B2; A = A2;
			 *
			 * === No need for 'T', we can write into 'Ex' instead since
			 * after the calculation of 'T' nobody is interested
			 * in 'Ex' anymore.
			 *
			 * E0 = E; D0 = D; C0 = C; B0 = B; A0 = A;
			 *
			 * E0 = E0 + s5(A0) + f(B0,C0,D0) + w[0] + K;
			 * B0 = s30(B0);
			 * E1 = D0; D1 = C0; C1 = B0; B1 = A0; A1 = E0;
			 *
			 * E1 = E1 + s5(A1) + f(B1,C1,D1) + w[1] + K;
			 * B1 = s30(B1);
			 * E2 = D1; D2 = C1; C2 = B1; B2 = A1; A2 = E1;
			 *
			 * E = Ex; D = Ex; C = Cx; B = Bx; A = Ax;
			 *
			 * === Further optimization: get rid of the swap operations
			 * Idea: instead of swapping the variables, swap the names of
			 * the used variables in the next step:
			 *
			 * E0 = E; D0 = d; C0 = C; B0 = B; A0 = A;
			 *
			 * E0 = E0 + s5(A0) + f(B0,C0,D0) + w[0] + K;
			 * B0 = s30(B0);
			 * // E1 = D0; D1 = C0; C1 = B0; B1 = A0; A1 = E0;
			 *
			 * D0 = D0 + s5(E0) + f(A0,B0,C0) + w[1] + K;
			 * A0 = s30(A0);
			 * E2 = C0; D2 = B0; C2 = A0; B2 = E0; A2 = D0;
			 *
			 * E = E2; D = D2; C = C2; B = B2; A = A2;
			 *
			 * === OK, let's do this several times, also, directly
			 * use A (instead of A0) and B,C,D,E.
			 *
			 * E = E + s5(A) + f(B,C,D) + w[0] + K;
			 * B = s30(B);
			 * // E1 = D; D1 = C; C1 = B; B1 = A; A1 = E;
			 *
			 * D = D + s5(E) + f(A,B,C) + w[1] + K;
			 * A = s30(A);
			 * // E2 = C; D2 = B; C2 = A; B2 = E; A2 = D;
			 *
			 * C = C + s5(D) + f(E,A,B) + w[2] + K;
			 * E = s30(E);
			 * // E3 = B; D3 = A; C3 = E; B3 = D; A3 = C;
			 *
			 * B = B + s5(C) + f(D,E,A) + w[3] + K;
			 * D = s30(D);
			 * // E4 = A; D4 = E; C4 = D; B4 = C; A4 = B;
			 *
			 * A = A + s5(B) + f(C,D,E) + w[4] + K;
			 * C = s30(C);
			 * // E5 = E; D5 = D; C5 = C; B5 = B; A5 = A;
			 *
			 * //E = E5; D = D5; C = C5; B = B5; A = A5;
			 *
			 * === Very nice, after 5 steps each variable
			 * has the same contents as after 5 steps with
			 * the original algorithm!
			 *
			 * We therefore can easily unroll each interval,
			 * as the number of steps in each interval is a
			 * multiple of 5 (20 steps per interval).
			 */
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | ((~B) & D)) + this.w[0] + 0x5A827999;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | ((~A) & C)) + this.w[1] + 0x5A827999;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | ((~E) & B)) + this.w[2] + 0x5A827999;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | ((~D) & A)) + this.w[3] + 0x5A827999;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | ((~C) & E)) + this.w[4] + 0x5A827999;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | ((~B) & D)) + this.w[5] + 0x5A827999;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | ((~A) & C)) + this.w[6] + 0x5A827999;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | ((~E) & B)) + this.w[7] + 0x5A827999;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | ((~D) & A)) + this.w[8] + 0x5A827999;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | ((~C) & E)) + this.w[9] + 0x5A827999;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | ((~B) & D)) + this.w[10] + 0x5A827999;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | ((~A) & C)) + this.w[11] + 0x5A827999;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | ((~E) & B)) + this.w[12] + 0x5A827999;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | ((~D) & A)) + this.w[13] + 0x5A827999;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | ((~C) & E)) + this.w[14] + 0x5A827999;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | ((~B) & D)) + this.w[15] + 0x5A827999;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | ((~A) & C)) + this.w[16] + 0x5A827999;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | ((~E) & B)) + this.w[17] + 0x5A827999;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | ((~D) & A)) + this.w[18] + 0x5A827999;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | ((~C) & E)) + this.w[19] + 0x5A827999;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[20] + 0x6ED9EBA1;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[21] + 0x6ED9EBA1;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[22] + 0x6ED9EBA1;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[23] + 0x6ED9EBA1;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[24] + 0x6ED9EBA1;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[25] + 0x6ED9EBA1;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[26] + 0x6ED9EBA1;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[27] + 0x6ED9EBA1;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[28] + 0x6ED9EBA1;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[29] + 0x6ED9EBA1;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[30] + 0x6ED9EBA1;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[31] + 0x6ED9EBA1;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[32] + 0x6ED9EBA1;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[33] + 0x6ED9EBA1;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[34] + 0x6ED9EBA1;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[35] + 0x6ED9EBA1;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[36] + 0x6ED9EBA1;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[37] + 0x6ED9EBA1;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[38] + 0x6ED9EBA1;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[39] + 0x6ED9EBA1;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D)) + this.w[40] + 0x8F1BBCDC;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C)) + this.w[41] + 0x8F1BBCDC;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B)) + this.w[42] + 0x8F1BBCDC;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A)) + this.w[43] + 0x8F1BBCDC;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E)) + this.w[44] + 0x8F1BBCDC;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D)) + this.w[45] + 0x8F1BBCDC;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C)) + this.w[46] + 0x8F1BBCDC;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B)) + this.w[47] + 0x8F1BBCDC;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A)) + this.w[48] + 0x8F1BBCDC;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E)) + this.w[49] + 0x8F1BBCDC;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D)) + this.w[50] + 0x8F1BBCDC;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C)) + this.w[51] + 0x8F1BBCDC;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B)) + this.w[52] + 0x8F1BBCDC;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A)) + this.w[53] + 0x8F1BBCDC;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E)) + this.w[54] + 0x8F1BBCDC;
			C = ((C << 30) | (C >>> 2));
	
			E = E + ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D)) + this.w[55] + 0x8F1BBCDC;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C)) + this.w[56] + 0x8F1BBCDC;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B)) + this.w[57] + 0x8F1BBCDC;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A)) + this.w[58] + 0x8F1BBCDC;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E)) + this.w[59] + 0x8F1BBCDC;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[60] + 0xCA62C1D6;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[61] + 0xCA62C1D6;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[62] + 0xCA62C1D6;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[63] + 0xCA62C1D6;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[64] + 0xCA62C1D6;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[65] + 0xCA62C1D6;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[66] + 0xCA62C1D6;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[67] + 0xCA62C1D6;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[68] + 0xCA62C1D6;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[69] + 0xCA62C1D6;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[70] + 0xCA62C1D6;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[71] + 0xCA62C1D6;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[72] + 0xCA62C1D6;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[73] + 0xCA62C1D6;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[74] + 0xCA62C1D6;
			C = ((C << 30) | (C >>> 2));
	
			E += ((A << 5) | (A >>> 27)) + (B ^ C ^ D) + this.w[75] + 0xCA62C1D6;
			B = ((B << 30) | (B >>> 2));
	
			D += ((E << 5) | (E >>> 27)) + (A ^ B ^ C) + this.w[76] + 0xCA62C1D6;
			A = ((A << 30) | (A >>> 2));
	
			C += ((D << 5) | (D >>> 27)) + (E ^ A ^ B) + this.w[77] + 0xCA62C1D6;
			E = ((E << 30) | (E >>> 2));
	
			B += ((C << 5) | (C >>> 27)) + (D ^ E ^ A) + this.w[78] + 0xCA62C1D6;
			D = ((D << 30) | (D >>> 2));
	
			A += ((B << 5) | (B >>> 27)) + (C ^ D ^ E) + this.w[79] + 0xCA62C1D6;
			C = ((C << 30) | (C >>> 2));
	
			this.H0 += A;
			this.H1 += B;
			this.H2 += C;
			this.H3 += D;
			this.H4 += E;
	
			// debug(80, H0, H1, H2, H3, H4);
		}
	
		private static String toHexString(byte[] b)
		{
			final String hexChar = "0123456789ABCDEF";
	
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < b.length; i++)
			{
				sb.append(hexChar.charAt((b[i] >> 4) & 0x0f));
				sb.append(hexChar.charAt(b[i] & 0x0f));
			}
			return sb.toString();
		}
	
		public static void main(String[] args)
		{
			SHA1 sha = new SHA1();
	
			byte[] dig1 = new byte[20];
			byte[] dig2 = new byte[20];
			byte[] dig3 = new byte[20];
	
			/*
			 * We do not specify a charset name for getBytes(), since we assume that
			 * the JVM's default encoder maps the _used_ ASCII characters exactly as
			 * getBytes("US-ASCII") would do. (Ah, yes, too lazy to catch the
			 * exception that can be thrown by getBytes("US-ASCII")). Note: This has
			 * no effect on the SHA-1 implementation, this is just for the following
			 * test code.
			 */
	
			sha.update("abc".getBytes());
			sha.digest(dig1);
	
			sha.update("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes());
			sha.digest(dig2);
	
			for (int i = 0; i < 1000000; i++)
				sha.update((byte) 'a');
			sha.digest(dig3);
	
			String dig1_res = toHexString(dig1);
			String dig2_res = toHexString(dig2);
			String dig3_res = toHexString(dig3);
	
			String dig1_ref = "A9993E364706816ABA3E25717850C26C9CD0D89D";
			String dig2_ref = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1";
			String dig3_ref = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F";
	
			if (dig1_res.equals(dig1_ref))
				System.out.println("SHA-1 Test 1 OK.");
			else
				System.out.println("SHA-1 Test 1 FAILED.");
	
			if (dig2_res.equals(dig2_ref))
				System.out.println("SHA-1 Test 2 OK.");
			else
				System.out.println("SHA-1 Test 2 FAILED.");
	
			if (dig3_res.equals(dig3_ref))
				System.out.println("SHA-1 Test 3 OK.");
			else
				System.out.println("SHA-1 Test 3 FAILED.");
	
			if (dig3_res.equals(dig3_ref))
				System.out.println("SHA-1 Test 3 OK.");
			else
				System.out.println("SHA-1 Test 3 FAILED.");
		}
	}
	
	/*Copyright (c) 2006 - 2011 Christian Plattner. All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:
	
	a.) Redistributions of source code must retain the above copyright
		notice, this list of conditions and the following disclaimer.
	b.) Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions and the following disclaimer in the
		documentation and/or other materials provided with the distribution.
	c.) Neither the name of Christian Plattner nor the names of its contributors may
		be used to endorse or promote products derived from this software
		without specific prior written permission.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
	
	
	This software includes work that was released under the following license:
	
	Copyright (c) 2005 - 2006 Swiss Federal Institute of Technology (ETH Zurich),
	  Department of Computer Science (http://www.inf.ethz.ch),
	  Christian Plattner. All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:
	
	a.) Redistributions of source code must retain the above copyright
		notice, this list of conditions and the following disclaimer.
	b.) Redistributions in binary form must reproduce the above copyright
		notice, this list of conditions and the following disclaimer in the
		documentation and/or other materials provided with the distribution.
	c.) Neither the name of ETH Zurich nor the names of its contributors may
		be used to endorse or promote products derived from this software
		without specific prior written permission.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
	
	
	The Java implementations of the AES, Blowfish and 3DES ciphers have been
	taken (and slightly modified) from the cryptography package released by
	"The Legion Of The Bouncy Castle".
	
	Their license states the following:
	
	Copyright (c) 2000 - 2004 The Legion Of The Bouncy Castle
	(http://www.bouncycastle.org)
	
	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:
	
	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.
	
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.*/

