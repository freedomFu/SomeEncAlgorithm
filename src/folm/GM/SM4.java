package folm.GM;

/**
 * SM4 分组密码算法
 * 分组长度128bit，密钥长度128bit，32轮
 * FK 和 CK 是系统参数
 * 术语：
 *  - 分组长度 block length
 *  - 密钥长度 key length
 *  - 密钥扩展算法 key expansion algorithm
 *  - 轮数 rounds
 *  - 字 word
 *  - S盒 S-box
 * 结构：
 *  -
 */
public class SM4 {
    private static long[] CK = {
            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
            0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
            0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
            0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
            0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
            0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
            0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
    };

    private static long[] FK = {
            0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC,
    };

    private static int[] s_box = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
        0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
        0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
        0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
        0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
        0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
        0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
        0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
        0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xbD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
        0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
    };

    public static void main(String[] args) {
        String plaintext = "0123456789ABCDEFFEDCBA9876543210";
        String key = "0123456789ABCDEFFEDCBA9876543210";
        String cipherText = encrypt(plaintext, key); // 128位bit密文
        System.out.println(cipherText);
        String decryptionText = decrypt(cipherText, key); // 128位bit解密后的明文
        System.out.println(decryptionText);
    }

    /**
     * SM4 加密算法
     * @param plaintext 明文串
     * @param key 密钥串
     * @return 加密后的密文串
     */
    public static String encrypt(String plaintext, String key){
        long[] X =splitText(plaintext);
        long[] K = expandKey(splitKey(key));
        for(int i=4;i<X.length;i++){
            X[i] = xor(X[i-4],L1(paraSbox(xor(X[i-3],X[i-2],X[i-1],K[i]))));
        }
        return adverseText(X);
    }

    /**
     * SM4 解密算法
     * @param ciphertext 密文串
     * @param key 密钥串
     * @return
     */
    public static String decrypt(String ciphertext, String key){
        long[] K = expandKey(splitKey(key));
        long[] X = splitText(ciphertext);
        for(int i=4,j=35;i<X.length;i++,j--){
            X[i] = xor(X[i-4],L1(paraSbox(xor(X[i-3],X[i-2],X[i-1],K[j]))));
        }
        return adverseText(X);
    }

    /**
     * 将128位bit的秘钥拆分为4个32位bit
     * @param key 密钥串
     * @return
     */
    private static long[] splitKey(String key){
        long[] MK = new long[4];
        for(int i=0;i<MK.length;i++){
            MK[i] = Long.parseLong(key.substring(i*8, i*8+8), 16);
        }
        return MK;
    }

    /**
     * 将128位bit的明文或密文拆分为4个32位bit
     * @param text 明文十六进制字符串
     * @return
     */
    private static long[] splitText(String text){
        long[] X = new long[36];
        for(int i=0;i<4;i++){
            X[i] = Long.parseLong(text.substring(i*8, i*8+8), 16);
        }
        return X;
    }

    /**
     * SM4的密钥扩展算法
     * 将4个32位bit的秘钥扩展为32个32位bit的轮秘钥，故长整型数组K[]的长度为36
     * @param MK 128位bit秘钥拆分的4个32位bit轮秘钥
     * @return 长度为36的长整型数组，仅前4位有赋值
     */
    private static long[] expandKey(long[] MK){
        long[] K = new long[36];
        K[0] = xor(MK[0], FK[0]);
        K[1] = xor(MK[1], FK[1]);
        K[2] = xor(MK[2], FK[2]);
        K[3] = xor(MK[3], FK[3]);
        for(int i=4;i<K.length;i++){
            K[i] = xor(K[i-4],L2(paraSbox(xor(K[i-3],K[i-2],K[i-1],CK[i-4]))));
        }
        return K;
    }

    /**
     * SM4算法中的反序变换
     * 将32位迭代的最后4条结果反序组成最终密文或明文
     * @param X 32轮迭代长整型数组
     * @return 反序变换后的结果，即最终密文或明文
     */
    private static String adverseText(long[] X){
        StringBuilder sb = new StringBuilder();
        for(int i=X.length-1;i>X.length-5;i--){
            String str = paddingZero(X[i], 8);
            sb.append(str);
        }
        return sb.toString();
    }

    /**
     * SM4中的一个S盒变换
     * @param a 8位的十六进制字符串 长度位2
     * @return S盒变换结果 长度为2
     */
    private static String sBox(String a){
        int x = charToNum(a.charAt(0));
        int y = charToNum(a.charAt(1));
        return paddingZero(s_box[x*16+y],2);
    }

    /**
     * SM4的4个并行S盒变换
     * @param l 32位输入
     * @return 4个并行S盒变换结果
     */
    private static long paraSbox(long l){
        String str = paddingZero(l,8);
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<8;i+=2){
            sb.append(sBox(str.substring(i,i+2)));
        }
        return Long.parseLong(sb.toString(),16);
    }

    /**
     * SM4中的线性变换
     * 即输入比特与其循环左移2位、10位、18位、24位异或的结果
     * @param b 32位输入 长整型
     * @return L 变换结果
     */
    private static long L1(long b){
        return xor(b, xor(leftShift(b, 2), leftShift(b, 10), leftShift(b, 18), leftShift(b, 24)));
    }

    private static long L2(long b){
        return xor(b, xor(leftShift(b, 13),leftShift(b,23)));
    }

    /**
     * 循环左移
     * @param l 32位 长整型
     * @param n 左移位数
     * @return 循环左移结果
     */
    private static long leftShift(long l, int n){
        String str = paddingZero(l, 8);
        // 转为二进制
        String binStr = strToBin(str);
        n = n % 32;
        String afterShiftBin = binStr.substring(n,binStr.length()) + binStr.substring(0, n);
        return Long.parseLong(binToStr(afterShiftBin),16);
    }

    /**
     * 在16进制字符串之前补充0到指定长度
     * @param l
     * @param length
     * @return
     */
    private static String paddingZero(long l, int length){
        String str = Long.toString(l,16);
        int padding = length - str.length();
        if(padding!=0){
            StringBuilder sb = new StringBuilder();
            for(int i=0;i<padding;i++){
                sb.append("0");
            }
            sb.append(str);
            return sb.toString();
        }else{
            return str;
        }
    }

    /**
     * 2个32位的整数的异或运算
     * 中长整型32位异或可能会溢出导致负值，故将结果与0xFFFFFFFFL再进行与运算，来保证结果正确
     * @param l1
     * @param l2
     * @return
     */
    private static long xor(long l1, long l2){
        long l = l1^l2;
        return l&0x0FFFFFFFFL;
    }

    /**
     * 4个32位数异或
     * @param l1
     * @param l2
     * @param l3
     * @param l4
     * @return 异或结果  32bit
     */
    private static long xor(long l1, long l2, long l3, long l4){
        return xor(l1,xor(l2,xor(l3,l4 & 0x0FFFFFFFFL)));
    }

    /**
     * 十六进制数组转换成二进制数组
     * @param str 十六进制数组
     * @return 二进制数组
     */
    private static String strToBin(String str){
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<str.length();i++){
            switch (str.charAt(i)){
                case '0':sb.append("0000");break;
                case '1':sb.append("0001");break;
                case '2':sb.append("0010");break;
                case '3':sb.append("0011");break;
                case '4':sb.append("0100");break;
                case '5':sb.append("0101");break;
                case '6':sb.append("0110");break;
                case '7':sb.append("0111");break;
                case '8':sb.append("1000");break;
                case '9':sb.append("1001");break;
                case 'A': case 'a':sb.append("1010");break;
                case 'B': case 'b':sb.append("1011");break;
                case 'C': case 'c':sb.append("1100");break;
                case 'D': case 'd':sb.append("1101");break;
                case 'E': case 'e':sb.append("1110");break;
                case 'F': case 'f':sb.append("1111");break;
                default:break;
            }
        }
        return sb.toString();
    }

    /**
     * 把二进制数组转成十六进制数组
     * @param bin 二进制数组
     * @return 十六进制数组
     */
    private static String binToStr(String bin){
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<bin.length();i+=4){
            switch (bin.substring(i, i+4)){
                case "0000": sb.append("0");break;
                case "0001": sb.append("1");break;
                case "0010": sb.append("2");break;
                case "0011": sb.append("3");break;
                case "0100": sb.append("4");break;
                case "0101": sb.append("5");break;
                case "0110": sb.append("6");break;
                case "0111": sb.append("7");break;
                case "1000": sb.append("8");break;
                case "1001": sb.append("9");break;
                case "1010": sb.append("A");break;
                case "1011": sb.append("B");break;
                case "1100": sb.append("C");break;
                case "1101": sb.append("D");break;
                case "1110": sb.append("E");break;
                case "1111": sb.append("F");break;
                default:break;
            }
        }
        return sb.toString();
    }

    /**
     * 将十六进制字符转成整型
     * @param c 字符
     * @return 整型结果
     */
    private static int charToNum(char c){
        switch (c){
            case '0': return 0;
            case '1': return 1;
            case '2': return 2;
            case '3': return 3;
            case '4': return 4;
            case '5': return 5;
            case '6': return 6;
            case '7': return 7;
            case '8': return 8;
            case '9': return 9;
            case 'A': case 'a': return 10;
            case 'B': case 'b': return 11;
            case 'C': case 'c': return 12;
            case 'D': case 'd': return 13;
            case 'E': case 'e': return 14;
            case 'F': case 'f': return 15;
            default: return -1;
        }
    }


}
