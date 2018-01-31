/*
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
*/
public class asiagaming{
	private static byte[] flag = new byte[]{-19, 116, 58, 108, -1, 33, 9, 61, -61, -37, 108, -123, 3, 35, 97, -10, -15, 15, -85, -66, -31, -65, 17, 79, 31, 25, -39, 95, 93, 1, -110, -103, -118, -38, -57, -58, -51, -79};
	private static byte[] k = new byte[]{9, 10, 13, 7, 17, 1, 19, 2};
	public static void main(String args[]) {
    	System.out.println(new String(_R.C(asiagaming.flag, asiagaming.k)));
	}
}


