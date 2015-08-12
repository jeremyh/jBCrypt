package org.mindrot;

/**
 * Encode/Decode a byte array using bcrypt's slightly-modified base64
 * encoding scheme. Note that this is *not* compatible with
 * the standard MIME-base64 encoding.
 * */
public class Base64 {
    // Table for Base64 encoding
    static private final char[] codes = {
        '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9'
    };
    // Table for Base64 decoding
    static private final byte[] indexes = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
        -1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
        7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        -1, -1, -1, -1, -1, -1, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
        51, 52, 53, -1, -1, -1, -1, -1
    };

    /**
     * Encode a byte array using bcrypt's slightly-modified base64
     * encoding scheme. Note that this is *not* compatible with
     * the standard MIME-base64 encoding.
     *
     * @param d	the byte array to encode
     * @param len	the number of bytes to encode
     * @return	base64-encoded string
     * @exception IllegalArgumentException if the length is invalid
     */
    static String encodeB64(byte d[], int len)
        throws IllegalArgumentException {
        int off = 0;
        StringBuffer rs = new StringBuffer();
        int c1, c2;

        if (len <= 0 || len > d.length)
            throw new IllegalArgumentException ("Invalid len");

        while (off < len) {
            c1 = d[off++] & 0xff;
            rs.append(codes[(c1 >> 2) & 0x3f]);
            c1 = (c1 & 0x03) << 4;
            if (off >= len) {
                rs.append(codes[c1 & 0x3f]);
                break;
            }
            c2 = d[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            rs.append(codes[c1 & 0x3f]);
            c1 = (c2 & 0x0f) << 2;
            if (off >= len) {
                rs.append(codes[c1 & 0x3f]);
                break;
            }
            c2 = d[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            rs.append(codes[c1 & 0x3f]);
            rs.append(codes[c2 & 0x3f]);
        }
        return rs.toString();
    }

    /**
     * Decode a string encoded using bcrypt's base64 scheme to a
     * byte array. Note that this is *not* compatible with
     * the standard MIME-base64 encoding.
     * @param s	the string to decode
     * @param maxolen	the maximum number of bytes to decode
     * @return	an array containing the decoded bytes
     * @throws IllegalArgumentException if maxolen is invalid
     */
    static byte[] decodeB64(String s, int maxolen)
        throws IllegalArgumentException {
        StringBuffer rs = new StringBuffer();
        int off = 0, slen = s.length(), olen = 0;
        byte ret[];
        byte c1, c2, c3, c4, o;

        if (maxolen <= 0)
            throw new IllegalArgumentException ("Invalid maxolen");

        while (off < slen - 1 && olen < maxolen) {
            c1 = char64(s.charAt(off++));
            c2 = char64(s.charAt(off++));
            if (c1 == -1 || c2 == -1)
                break;
            o = (byte)(c1 << 2);
            o |= (c2 & 0x30) >> 4;
            rs.append((char)o);
            if (++olen >= maxolen || off >= slen)
                break;
            c3 = char64(s.charAt(off++));
            if (c3 == -1)
                break;
            o = (byte)((c2 & 0x0f) << 4);
            o |= (c3 & 0x3c) >> 2;
            rs.append((char)o);
            if (++olen >= maxolen || off >= slen)
                break;
            c4 = char64(s.charAt(off++));
            o = (byte)((c3 & 0x03) << 6);
            o |= c4;
            rs.append((char)o);
            ++olen;
        }

        ret = new byte[olen];
        for (off = 0; off < olen; off++)
            ret[off] = (byte)rs.charAt(off);
        return ret;
    }

    /**
     * Look up the 3 bits base64-encoded by the specified character,
     * range-checking againt conversion table
     * @param x	the base64-encoded value
     * @return	the decoded value of x
     */
    private static byte char64(char x) {
        if ((int)x < 0 || (int)x > indexes.length)
            return -1;
        return indexes[(int)x];
    }
}
