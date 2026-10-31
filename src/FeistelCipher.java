import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Educational Feistel cipher with 8-bit and 16-bit blocks. */
public class FeistelCipher {
    public static void main(String[] args) {
        try {
            run(args);
        } catch (IllegalArgumentException | IOException error) {
            System.err.println("Error: " + error.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException {
        if (args.length != 5) {
            throw new IllegalArgumentException(
                "Usage: java FeistelCipher <input> <output> <keys> <e|d> <8|16>");
        }
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        String keys = args[2];
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("The key must contain at least one character.");
        }
        if (!args[3].equals("e") && !args[3].equals("d")) {
            throw new IllegalArgumentException("Operation must be e (encrypt) or d (decrypt).");
        }
        if (!args[4].equals("8") && !args[4].equals("16")) {
            throw new IllegalArgumentException("Block size must be 8 or 16.");
        }
        boolean encrypt = args[3].equals("e");
        int blockSize = Integer.parseInt(args[4]);
        if (input.toAbsolutePath().normalize().equals(output.toAbsolutePath().normalize())
                || (Files.exists(output) && Files.isSameFile(input, output))) {
            throw new IllegalArgumentException("Input and output must be different files.");
        }
        byte[] data = Files.readAllBytes(input);
        if (blockSize == 16 && !encrypt && data.length % 2 != 0) {
            throw new IllegalArgumentException("16-bit ciphertext must contain an even number of bytes.");
        }
        if (blockSize == 16 && encrypt && data.length % 2 != 0) {
            System.err.println("Note: adding one zero padding byte. Decryption will retain it.");
        }
        byte[] result = blockSize == 16
            ? feistel16(data, keys, encrypt) : feistel8(data, keys, encrypt);
        Files.write(output, result);
        System.out.println("Done! Wrote " + result.length + " bytes to " + output);
    }

    //16-bit Feistel: processes 2-byte blocks (L,R) using GF(2^8) in F(R,key)
    private static byte[] feistel16(byte[] data, String keys, boolean encrypt) {
        int rounds = keys.length();
        int[] rk = new int[rounds];
        for (int i = 0; i < rounds; i++) rk[i] = keys.charAt(i) & 0xFF;

        //Reverse order for decryption
        if (!encrypt) {
            for (int i = 0, j = rounds - 1; i < j; i++, j--) {
                int t = rk[i]; rk[i] = rk[j]; rk[j] = t;
            }
        }

        int blocks = (data.length + 1) / 2;
        byte[] out = new byte[blocks * 2];

        for (int b = 0; b < blocks; b++) {
            int i = b * 2;

            int L; //Left block
            if (i < data.length) {
                L = data[i] & 0xFF;   //Left byte exists
            } else {
                L = 0;                //Padding for missing byte
            }
            int R; //Right block
            if (i + 1 < data.length) {
                R = data[i+1] & 0xFF;  //Right byte exists
            } else {
                R = 0;                 //Padding if last block has only 1 byte
            }

            for (int r = 0; r < rounds; r++) {
                int f = gf8(R, rk[r]); //Round function: multiply R by the round key in GF(2^8)
                int newL = R;          //Left becomes the previous right half
                int newR = L ^ f;      //new R = previous L XOR F output
                L = newL;
                R = newR;
            }

            //Final swap before writing
            out[i]   = (byte)(R & 0xFF);
            out[i+1] = (byte)(L & 0xFF);
        }
        return out;
    }

    //8-bit Feistel: splits each byte into two 4-bit halves (L,R) and uses GF(2^4) in F(R,key)
    private static byte[] feistel8(byte[] data, String keys, boolean encrypt) {
        int rounds = keys.length();
        int[] rk = new int[rounds];
        for (int i = 0; i < rounds; i++) rk[i] = keys.charAt(i) & 0x0F;

        if (!encrypt) {
            for (int i = 0, j = rounds - 1; i < j; i++, j--) {
                int t = rk[i]; rk[i] = rk[j]; rk[j] = t;
            }
        }

        byte[] out = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            int val = data[i] & 0xFF;
            int L = (val >> 4) & 0x0F; //High nibble -> left half
            int R = val & 0x0F;        //Low nibble -> right half

            for (int r = 0; r < rounds; r++) {
                int f = gf4(R, rk[r]);     //Round function in GF(2^4)
                int newL = R;
                int newR = (L ^ f) & 0x0F; //Right becomes L XOR F(R, key)
                L = newL;
                R = newR;
            }
            int outByte = ((R & 0x0F) << 4) | (L & 0x0F);
            out[i] = (byte)outByte;
        }
        return out;
    }

    //GF(2^8) multiply with modulus 0x11B
    private static int gf8(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1) p ^= a;
            boolean carry = (a & 0x80) != 0;
            a <<= 1;
            if (carry) a ^= 0x11B;
            a &= 0xFF;
            b >>= 1;
        }
        return p & 0xFF;
    }

    //GF(2^4) multiply with modulus 0x13 (x^4 + x + 1)
    private static int gf4(int a, int b) {
        int p = 0;
        for (int i = 0; i < 4; i++) {
            if ((b & 1) == 1) p ^= a;
            boolean carry = (a & 0x8) != 0; // bit 3
            a <<= 1;
            if (carry) a ^= 0x13;
            a &= 0x0F;
            b >>= 1;
        }
        return p & 0x0F;
    }
}
