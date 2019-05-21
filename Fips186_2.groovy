//package com.ericsson.esv.auth;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Fips186_2
{
	/*
	 * Pseudo random number generator. Generates totally not random number based on the seed. So I guess it's better
	 * referred to as simply a number generator.
	 */

	static int fips186_2_prf2(byte[] xKeyBytes, byte[] out)
	{
		BigInteger xKey = fromByteArray(xKeyBytes);

		ByteBuffer outBuf = ByteBuffer.wrap(out);

		int m = out.length / 40;

		// Use custom class so we can extract internal SHA state.
		SHA1 digester = new SHA1();

		BigInteger mod = new BigInteger("2").pow(xKeyBytes.length * 8);

		for (int j = 0; j < m; j++)
		{

			for (int i = 0; i < 2; i++)
			{
				/* XVAL = (XKEY + XSEED_j) mod 2^b */
				BigInteger xVal = xKey;

				/* w_i = G(t, XVAL) */

				// Pad the value such that
				// 1: BigInteger is 20 bytes (remove the sign byte)
				// 2: Total bytes are 64 (trigger SHA-1 update)
				// 3: DO NOT PERFORM FINAL SHA-1 DIGEST.
				byte[] bs = toByteArray(xVal, 20);

				byte[] arr = Arrays.copyOf(bs, 64);
				digester.update(arr);

				// The internal values for H0...4 from the calculation are extracted.
				// It is NOT POSSIBLE to use the public digest APIs (they WILL add extra info)
				ByteBuffer wBuf = ByteBuffer.allocate(20);
				wBuf.putInt(digester.H0);
				wBuf.putInt(digester.H1);
				wBuf.putInt(digester.H2);
				wBuf.putInt(digester.H3);
				wBuf.putInt(digester.H4);

				BigInteger wi = fromByteArray(wBuf.array());

				digester = new SHA1();

				/* XKEY = (1 + XKEY + w_i) mod 2^b */
				xKey = xKey.add(BigInteger.ONE);
				xKey = xKey.add(wi);
				xKey = xKey.mod(mod);

				//x_j = w_0|w_1
				// This means, just append the current wi value to out
				// Note this differs from FIPS186_2; see RFC 4186 for example
				outBuf.put(toByteArray(wi, 20));
			}
		}

		return 0;

	}

	/**
	 * Convert a biginteger to a byte array, either snipping or zero-padding the
	 * leftmost bytes to fit.
	 *
	 * @param bi
	 * @param length
	 * @return
	 */
	static byte[] toByteArray(BigInteger bi, int length)
	{
		byte[] bs = bi.toByteArray();

		if (bs.length == length)
			return bs;

		if (bs.length > length)
		{
			return Arrays.copyOfRange(bs, bs.length - length, bs.length);
		}

		byte[] rv = new byte[length];
		System.arraycopy(bs, 0, rv, length - bs.length, bs.length);
		return rv;
	}

	/**
	 * Makes a positively signed big integer from an array by zero-padding the
	 * left.
	 *
	 * @param arr
	 * @return
	 */
	static BigInteger fromByteArray(byte[] arr)
	{
		byte[] src = new byte[arr.length + 1];
		System.arraycopy(arr, 0, src, 1, arr.length);
		src[0] = 0; // Sign as positive
		return new BigInteger(src);
	}

}
