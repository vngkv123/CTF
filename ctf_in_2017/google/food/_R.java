public class _R{
	public static byte[] C(byte[] arg8, byte[] arg9) {
        int v7 = 256;
        byte[] v3 = new byte[v7];
        byte[] v4 = new byte[v7];
        int v0 = 0;
        int v1;
        for(v1 = 0; v1 != v7; ++v1) {
            v3[v1] = ((byte)v1);
            v4[v1] = arg9[v1 % arg9.length];
        }

        int v2 = v1 ^ v1;
        v1 = 0;
        while(v2 != v7) {
            v1 = v1 + v3[v2] + v4[v2] & 255;
            v3[v1] = ((byte)(v3[v1] ^ v3[v2]));
            v3[v2] = ((byte)(v3[v2] ^ v3[v1]));
            v3[v1] = ((byte)(v3[v1] ^ v3[v2]));
            ++v2;
        }

        v4 = new byte[arg8.length];
        v2 ^= v2;
        v1 ^= v1;
        while(v0 != arg8.length) {
            v2 = v2 + 1 & 255;
            v1 = v1 + v3[v2] & 255;
            v3[v1] = ((byte)(v3[v1] ^ v3[v2]));
            v3[v2] = ((byte)(v3[v2] ^ v3[v1]));
            v3[v1] = ((byte)(v3[v1] ^ v3[v2]));
            v4[v0] = ((byte)(arg8[v0] ^ v3[v3[v2] + v3[v1] & 255]));
            ++v0;
        }

        return v4;
    }
}
