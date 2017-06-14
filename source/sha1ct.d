module sha1ct;
import std.uuid : UUID;

private ubyte[4] ctfeUIntToBigEndian(uint u) @safe pure nothrow @nogc
{
	return cast(ubyte[4])[(u >> 24) & 0xFF, (u >> 16) & 0xFF, (u >> 8) & 0xFF, u & 0xFF];
}

private ubyte[8] ctfeULongToBigEndian(ulong u) @safe pure nothrow @nogc
{
	return cast(ubyte[8])[(u >> 56) & 0xFF, (u >> 48) & 0xFF, (u >> 40) & 0xFF,
		(u >> 32) & 0xFF, (u >> 24) & 0xFF, (u >> 16) & 0xFF, (u >> 8) & 0xFF, u & 0xFF];
}

private uint rotateLeft(uint x, uint n) @safe pure nothrow @nogc
{
	return (x << n) | (x >> (32 - n));
}

private uint rotateRight(uint x, uint n) @safe pure nothrow @nogc
{
	return (x >> n) | (x << (32 - n));
}

struct SHA1
{
	void put(ubyte[64] block) @safe pure @nogc nothrow
	{
		uint[80] w;
		for (int i = 0; i < 16; i++)
		{
			ubyte[4] part;
			part[0] = block[i * 4];
			part[1] = block[i * 4 + 1];
			part[2] = block[i * 4 + 2];
			part[3] = block[i * 4 + 3];
			w[i] = (part[0] << 24) | (part[1] << 16) | (part[2] << 8) | part[3];
		}
		for (int i = 16; i < 80; i++)
			w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotateLeft(1);

		uint a = h[0];
		uint b = h[1];
		uint c = h[2];
		uint d = h[3];
		uint e = h[4];
		uint f;
		uint k;
		uint tmp;

		for (int i = 0; i < 80; i++)
		{
			if (i < 20)
			{
				f = (b & c) | (~b & d);
				k = 0x5A827999;
			}
			else if (i < 40)
			{
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}
			else if (i < 60)
			{
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}
			else
			{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			tmp = a.rotateLeft(5) + f + e + k + w[i];
			e = d;
			d = c;
			c = b.rotateLeft(30);
			b = a;
			a = tmp;
		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
	}

	ubyte[20] sum() @safe pure @nogc nothrow
	{
		ubyte[20] ret;
		ret[0 .. 4] = h[0].ctfeUIntToBigEndian;
		ret[4 .. 8] = h[1].ctfeUIntToBigEndian;
		ret[8 .. 12] = h[2].ctfeUIntToBigEndian;
		ret[12 .. 16] = h[3].ctfeUIntToBigEndian;
		ret[16 .. 20] = h[4].ctfeUIntToBigEndian;
		return ret;
	}

	uint[5] h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
}

ubyte[20] sha1Of(in char[] s) pure nothrow
{
	return sha1Of(cast(ubyte[]) s);
}

ubyte[20] sha1Of(ubyte[] bytes) @safe pure nothrow
{
	SHA1 builder;
	auto len = bytes.length;
	bytes ~= 0b1000_0000;
	if (bytes.length % 64 > 56)
		bytes.length = (bytes.length & ~63) + 128;
	else
		bytes.length = (bytes.length & ~63) + 64;
	ubyte[8] b = (cast(ulong) len * 8).ctfeULongToBigEndian;
	bytes[$ - 8 .. $] = b;
	auto blocks = bytes.length / 64;
	assert(bytes.length % 64 == 0);
	for (int i = 0; i < blocks; i++)
		builder.put(bytes[i * 64 .. i * 64 + 64][0 .. 64]);
	return builder.sum;
}

UUID sha1UUID(in char[] data, const UUID namespace = UUID.init) pure nothrow
{
	return sha1UUID(cast(ubyte[]) data, namespace);
}

UUID sha1UUID(ubyte[] data, const UUID namespace = UUID.init) @safe pure nothrow
{
	auto hash = sha1Of(namespace.data ~ data);
	auto u = UUID();
	u.data[] = hash[0 .. 16];

	//set variant
	//must be 0b10xxxxxx
	u.data[8] &= 0b10111111;
	u.data[8] |= 0b10000000;

	//set version
	//must be 0b0101xxxx
	u.data[6] &= 0b01011111;
	u.data[6] |= 0b01010000;

	return u;
}

unittest
{
	import std.digest.digest;
	import std.digest.sha : sha1Orig = sha1Of;
	import std.uuid : origUUID = sha1UUID;

	string longString()
	{
		char[] ret;
		for (int i = 0; i < 1652; i++)
			ret ~= cast(char) i;
		return ret.idup;
	}

	enum test = longString;
	enum result = sha1Of(test);
	enum uuid = sha1UUID(test);
	enum namespace = sha1UUID("my.app");
	enum namespacedUuid = sha1UUID(test, namespace);
	assert(sha1Orig(test) == result, "\n" ~ sha1Orig(test)
			.toHexString ~ " !=\n" ~ result.toHexString);
	assert(origUUID(test) == uuid, "\n" ~ origUUID(test).toString ~ " !=\n" ~ uuid.toString);
	assert(origUUID(test, namespace) == namespacedUuid, "\n" ~ origUUID(test,
			namespace).toString ~ " !=\n" ~ namespacedUuid.toString);
}

/// README
unittest
{
	enum hash = sha1Of(cast(ubyte[])[0, 1, 2, 3]); // Binary Data
	enum hash2 = sha1Of("Hello World"); // String
	enum namespace = sha1UUID("my.app"); // generates a std.uuid.UUID from string or binary
	enum uuid = sha1UUID("interface1", namespace); // also with namespaces
}
