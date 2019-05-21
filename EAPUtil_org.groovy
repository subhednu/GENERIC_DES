//package com.ericsson.esv.auth
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//LDAP Search for -> 310260563291425
//EAP Identity: 0310260563291425@nai.epc.mnc260.mcc310.3gppnetwork.org
//              30333130323630353633323931343235406E61692E6570632E6D6E633236302E6D63633331302E336770706E6574776F726B2E6F7267
//              MDMxMDI2MDU2MzI5MTQyNUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn
//Found Zh LDAP AUTN -> D60699911A45000035B3C73009FC037E, size = 1, len = 16
//Found Zh LDAP CK   -> DFA765DA5970D1B9B256B91DB973E4C9, size = 1, len = 16
//Found Zh LDAP IK   -> AA4FF28767012746D726CB1EBCE0563A, size = 1, len = 16
//Found Zh LDAP RAND -> 5B90FB1F9B2A58C8122672D96AB9A18B, size = 1, len = 16
//Found Zh LDAP XRES -> 0C6214FFCFCDA8FA, size = 1, len = 8
//Rand = 0x5B90FB1F9B2A58C8122672D96AB9A18B
//Autn = 0xD60699911A45000035B3C73009FC037E
//Challenge = 0x0100003017010000010500005B90FB1F9B2A58C8122672D96AB9A18B02050000D60699911A45000035B3C73009FC037E
//RES : [12, 98, 20, -1, -49, -51, -88, -6] 
//
// Added authentication vectors in the following order in the tables:
// 310260563291425    <--0	
// 310260132787159    <--1
// 310260132787160    <--2
// 310260132787161    <--3
// 310260132787162    <--4
// 310260132787165    <--5
// 310260132787166    <--6
// 310260578863576    <--7
// 310260132787130    <--8
// 310260579525764    <--9
// 310260132773915    <--10
// 310260563291342	 <--11
// 310260126651975	 <--12
// 310260579002968    <--13
// 310260009251482    <--14
// 310260009251376    <--15
// 310310990004614    <--16
// 310310990004615    <--17
// 310310990004616    <--18
// 310310990004617    <--19
// 310310990004618    <--20
// 310310990003916    <--21
// 310310990003917    <--22
// 310310990003918    <--23
// 310310990003919    <--24
// 310310990003920    <--25




class EAPUtil {
	def static String[] IK = [	"AA4FF28767012746D726CB1EBCE0563A",
					"D2E0B542D77013EC647AE4BE1C39565A",
					"FE0868D82AB8063BDBC36D9A522209E2",
					"63F54F1F6207D3177BAAD20134FA39DE",
					"E49FF055FC247137FB5D938B884C779A",
					"43A8A787381F8AAD8F7C699775C7E191",
					"C161D41CD64B944FC1A2FE7B2663C861",
					"8E49A5C24BDFFA488E7ABD933E3A0DFF",
					"B8B8100603C8BAA430484DACA50F2274",
					"06BCCFCD138910AB4A6F1D8894F9545C",
					"C2A674BA14114799E39A33A1E7B32141",
					"7645AD95AF89B2889E611FF1EF42F493",
					"53F70087896CA31E1703F32927681B2F",
                           "28ACE239FF1401F7B55050D69A95286A",
                           "A0CEA8FE88A87202C87C0FA51E28D728",
                           "8C319F2687407DF243D4754D7F1F8525",
                           "356060f435a1bc7c60f3ff8bc3ce7def",
                           "f1545ca40f68a6544c31c807bcd2271e",
                           "f1c876a08d4bb18879985c9c45aa81b7",
                           "cf8682bf90a9782843c2ecf37c55a6cb",
                           "c75d82825593b102184f004feb0c7f6f",
                           "32c805e62bc1fc56f6ed1fe272662e6a",
                           "4241b2578002fbcd8c2a3d44067c2200",
                           "a225fa0e554ca070971a6025e453c050",
                           "be1c7a18e2827d937e35592718d432d2",
                           "48681e65938ac04e19b6741a42c4efdb"                           
					 ];
	def static String[] CK = [	"DFA765DA5970D1B9B256B91DB973E4C9",
					"8868E6C64AD8B9F34C3D4B0B93264075",
					"4CF5F011B28C43126A1D459672B746D5",
					"4A3E0970D29D588E2CD1FE3C3382ED5E",
					"4A51F3EBE4B8D86AB28356FA53547ADB",
					"50D0D2E002711265D28AA57ED50D5CC0",
  					"85C3C5D3ACA36D64F3342F6ADC9FC571",
					"D45EE3A4A37E87858E4A7BECC1ED11BA",
					"46537AE8A0D64E922CE25AAEFC5F98E3",
					"69F82DFA95E8211A93655C267F9492F5",
					"F96A5FCD0F84F5DD06258F1249170C3B",
					"C180AD872A84914C327B4E3F24784C8B",
					"8F3067A20B14D8BF407B3DE7B40CE4E2",
                           "62CCAC634DA23FEFFE4F3FB6D28A4CE4",
                           "94830384BAD7EC3DC7ED50240C6C6A63",
                           "05BF252B2F366C01C646B183C3A04492",
                           "a9f0e0496be85f49195928be2c4d8d97",
                           "cbe133bed222951a6058adbcc2df3475",
                           "2b986d791722bebbdb6c1756e4b730bd",
                           "67213df8f10efdbceeaf5010f3a5a844",
                           "c329fb041c5dca9613a0f4a344b456a9",
                           "e46e4e13785667ea14ff2747edf7fb50",
                           "63cec72756f75d689e52202ee5b0d866",
                           "232cb14a9adfe9e3339977f8d6822398",
                           "189cfaa3276b366d4d6736e12e963ff8",
                           "4a2c8dc5e1303321e559796eb3e2bc95"
					];
	def static String[] IDENTITY = ["MDMxMDI2MDU2MzI5MTQyNUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE1OUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE2MEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE2MUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE2MkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE2NUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzE2NkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDU3ODg2MzU3NkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc4NzEzMEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDU3OTUyNTc2NEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEzMjc3MzkxNUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDU2MzI5MTM0MkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
					"MDMxMDI2MDEyNjY1MTk3NUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",
        "MDMxMDI2MDU3OTAwMjk2OEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDI2MDAwOTI1MTQ4MkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDI2MDAwOTI1MTM3NkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwNDYxNEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwNDYxNUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwNDYxNkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwNDYxN0BuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwNDYxOEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwMzkxNkBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwMzkxN0BuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwMzkxOEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwMzkxOUBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn",

"MDMxMDMxMDk5MDAwMzkyMEBuYWkuZXBjLm1uYzI2MC5tY2MzMTAuM2dwcG5ldHdvcmsub3Jn"
					];
	def static final byte[][] 	RES=[	[12, 98, 20, -1, -49, -51, -88, -6],
						[-18, 106, 25, -65, -79, -50, 2, 53],
						[-52, -45, -65, 7, 19, 125, -41, 106],
						[45, -82, -9, -30, -53, 30, 11, 74],
						[-95, -41, 8, 116, 12, 4, 42, -75],
						[22, 127, -58, -18, 55, 72, 36, 100],
						[-107, 10, -48, -14, 5, 2, -32, 28],
						[11, -29, -96, 56, 117, -27, -82, -87],
						[100, 29, -67, -28, 83, -69, 26, -83],
						[80, 0, 98, -113, -53, -70, 71, -88],
						[-108, -24, 107, 105, -37, 17, -76, 29],
						[63, -23, -107, 68, 78, -2, -97, -58],
						[-39, -93, -128, 80, 112, 99, 14, -106],
                                [-78,  64,  83, -53,  110, 58, 120, 113],
                                [42, -62, 78, -35, 32, 109, -35, -126],
                                [60, -38, 41, -58, 109, -30, -85, 119],
                                [-24, 51, -103, -95, 10, 80, -27, -87],
                                [115, -38, -78, -26, 36, -123, 126, -108],
                                [111, -77, -125, -66, -102, -102, 47, 38],
                                [38, 119, -29, 55, 127, -46, -38, -14],
                                [-107, 25, -77, 107, -18, 85, -2, -22],
                                [111, -91, 32, 96, -57, -80, -41, 25],

                                [89, 41, -117, 7, 109, 47, 101, 76],
                                [6, 87, -3, 75, 42, 37, 106, -94],
                                [-13, 54, 34, 77, 97, -116, -36, 94],
                                [66, 56, -30, 60, 82, 43, 24, 43] 
					];


	def static byte[]			identity;
	def static byte[]			ik;
	def static byte[]			ck;

	
	def static byte[]			mk;
	def static byte[]			k_encr;
	def static byte[]			k_aut;
	def static byte[]			msk;
	def static byte[]			emsk;
	
	def static final int	EAP_SIM_NONCE_S_LEN		= 16;
	def static final int	EAP_SIM_NONCE_MT_LEN		= 16;
	def static final int	EAP_SIM_MAC_LEN			= 16;
	def static final int	EAP_SIM_MK_LEN			= 20;
	def static final int	EAP_SIM_K_AUT_LEN		= 16;
	def static final int	EAP_SIM_K_ENCR_LEN		= 16;
	def static final int	EAP_SIM_KEYING_DATA_LEN		= 64;
	def static final int	EAP_SIM_IV_LEN			= 16;
	def static final int	EAP_SIM_KC_LEN			= 8;
	def static final int	EAP_SIM_SRES_LEN		= 4;
	def static final int	EAP_EMSK_LEN			= 64;
	
	
	def static deriveMk()
	{

		/* MK = SHA1(Identity|IK|CK) */

		MessageDigest sha;


		try
		{
			sha = MessageDigest.getInstance("SHA-1");
			sha.update(identity);
			sha.update(ik);
			sha.update(ck);
			mk = sha.digest();

		}
		// No SHA-1? Yeah, right
		catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}

	def static int deriveKeys(byte[] mk, log)
	{
		byte[] buf = new byte[EAP_SIM_K_ENCR_LEN + EAP_SIM_K_AUT_LEN + EAP_SIM_KEYING_DATA_LEN + EAP_EMSK_LEN];

		// Snazzy secret "random" number generator will generate the same value on client and server. How random is that?
		Fips186_2.fips186_2_prf2(mk, buf);

		int pos = 0;
		byte[] mb = new byte[EAP_SIM_K_ENCR_LEN];
		System.arraycopy(buf, pos, mb, 0, EAP_SIM_K_ENCR_LEN);
		pos += EAP_SIM_K_ENCR_LEN;
		k_encr= mb;

		mb = new byte[EAP_SIM_K_AUT_LEN];
		System.arraycopy(buf, pos, mb, 0, EAP_SIM_K_AUT_LEN);
		pos += EAP_SIM_K_AUT_LEN;
		k_aut = mb;

		mb = new byte[EAP_SIM_KEYING_DATA_LEN];
		System.arraycopy(buf, pos, mb, 0, EAP_SIM_KEYING_DATA_LEN);
		pos += EAP_SIM_KEYING_DATA_LEN;
		msk = mb;

		mb = new byte[EAP_EMSK_LEN];
		System.arraycopy(buf, pos, mb, 0, EAP_EMSK_LEN);
		emsk = mb;

		return 0;
	}

	def static byte[] doMac(byte[] k_aut, byte[] messageWithZeroMac)
	{

		try
		{

			SecretKeySpec signingKey = new SecretKeySpec(k_aut, "HmacSHA1");

			// Get an hmac_sha1 Mac instance and initialize with the signing key
			Mac hmac = Mac.getInstance("HmacSHA1");
			hmac.init(signingKey);

			// Compute the hmac on input data bytes
			byte[] rawHmac = hmac.doFinal(messageWithZeroMac);

			return Arrays.copyOf(rawHmac, 16);

		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}

	}
	
	def static String makePayload(String base64Challenge, org.apache.log4j.Logger log, int index)
	{
// From the challenge, get the identifier from the EAP Header:
		byte[] data = DatatypeConverter.parseBase64Binary(base64Challenge);
		byte identifier = data[1];
		log.info "IDENTIFIER FROM CHALLENGE: "+identifier;


		identity=DatatypeConverter.parseBase64Binary(IDENTITY[index]);
		ik=DatatypeConverter.parseHexBinary(IK[index]);
		ck=DatatypeConverter.parseHexBinary(CK[index]);

		// Build the payload, with zero'd MAC value
		ByteBuffer zeroMacMsg = ByteBuffer.allocate(40);

		zeroMacMsg.put((byte) 2);   //EAP RESPONSE
		zeroMacMsg.put(identifier); //Identifier, not used
		short len = 40;
		zeroMacMsg.putShort(len);
		
		zeroMacMsg.put((byte) 23);  //EAP-AKA (Type)
		zeroMacMsg.put((byte) 1);   //AKA-CHALLENGE (SubType)
		zeroMacMsg.putShort((short) 0);     //Reserved
		
		zeroMacMsg.put((byte) 3);   //AT_RES
		zeroMacMsg.put((byte) 3);   //length (multiple of 4 bytes)
		zeroMacMsg.putShort((short) 64);    //RES length (bits)
		zeroMacMsg.put(RES[index]);        //RES
		
		zeroMacMsg.put((byte) 11);  //AT_MAC
		zeroMacMsg.put((byte) 5);   //length
		zeroMacMsg.putShort((short) 0);     //Reserved
		
		ByteBuffer payload =  zeroMacMsg.duplicate()
		byte[] rest = new byte[16];
		zeroMacMsg.put(rest);       //Zero'd MAC
		
		
		log.info "THE ZERO'd MAC PAYLOAD IS: " + zeroMacMsg.array()

	        deriveMk();
        	deriveKeys(mk,log);
		byte[] mac;
        	mac	= doMac(k_aut, zeroMacMsg.array());
		
		
		log.info "MAC is: " + mac
		payload.put(mac)
		log.info "ZEROMAC :" + zeroMacMsg.array()
		log.info "PAYLOAD :" + payload.array()
		return DatatypeConverter.printBase64Binary(payload.array());
		

	}
}
