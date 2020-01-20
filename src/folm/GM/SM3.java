package folm.GM;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * SM3国密标准 杂凑算法实现
 * @author 寻枫26
 */
public class SM3 {
    // 16进制
    private static char[] hexDigit = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    private static final String ivHexStr = "7380166f 4914b2b9 172442d7 da8a0600 a96f30bc 163138aa e38dee4d b0fb0e4e";
    // 输出对应的10进制数字
    private static final BigInteger IV = new BigInteger(ivHexStr.replaceAll(" ", ""), 16);

    private static final Integer Tj015 = Integer.valueOf("79cc4519", 16);
    private static final Integer Tj1663 = Integer.valueOf("7a879d8a", 16);
    private static final byte[] OnePadding = {(byte)0x80};
    private static final byte[] ZeroPadding = {(byte)0x00};

    // 根据j值获取T的值
    private static int T(int j){
        if(j>=0 && j<=15){
            return Tj015;
        }else if(j>=16 && j<= 63){
            return Tj1663;
        }else{
            throw new RuntimeException("data invalid");
        }
    }

    // 两个布尔函数 FF 和 GG
    private static Integer FF(Integer x, Integer y, Integer z, int j){
        if(j>=0 && j<=15){
            return x ^ y ^ z;
        }else if(j>=16 && j<=63){
            return (x&y) | (x&z) | (y&z);
        }else{
            throw new RuntimeException("data invalid");
        }
    }

    private static Integer GG(Integer x, Integer y, Integer z, int j){
        if(j>=0 && j<=15){
            return x ^ y ^ z;
        }else if(j>=16 && j<=63){
            return (x&y) | (~x&z);
        }else{
            throw new RuntimeException("data invalid");
        }
    }

    // 置换函数 P0 和 P1
    private static Integer P0(Integer x){
        return x^Integer.rotateLeft(x,9)^Integer.rotateLeft(x,17);
    }

    private static Integer P1(Integer x){
        return x^Integer.rotateLeft(x,15)^Integer.rotateLeft(x,23);
    }

    // 填充字节至512的倍数
    private static byte[] padding(byte[] source) throws IOException {
        // 长度不能大于2^64个bit 即 2^61个byte
        if(source.length > 0x2000000000000000L){
            throw new RuntimeException("source data invalid");
        }
        long l = source.length * 8;
        long k = 448 - (l+1) % 512;
        // 如果k<0，就需要多补充一个512，以保证k值非负
        if(k<0){
            k+=512;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(source);
        baos.write(OnePadding);
        // 填充时先添加“1”到消息的末尾，再添加k个0，所以k要减去7然后是要添加
        long i = k-7;
        while(i>0){
            baos.write(ZeroPadding);
            i-=8;
        }
        baos.write(long2byte(l));
        return baos.toByteArray();
    }
    // 把long类型的数值转换称byte数组存储起来
    private static byte[] long2byte(long l){
        byte[] bytes = new byte[8];
        for(int i=0;i<8;i++){
            // 存储的时候需要转换称byte类型才可以存储起来  右移1位除以2
            bytes[i] = (byte)(l>>>((7-i)*8));
        }
        return bytes;
    }

    // hash函数供调用
    public static byte[] hash(byte[] source) throws IOException {
        byte[] m1 = padding(source);
        int n = m1.length / (512/8);
        byte[] b;
        byte[] vi = IV.toByteArray();
        byte[] vi1 = null;
        for(int i=0;i<n;i++){
            b = Arrays.copyOfRange(m1, i*64, (i+1)*64);
            // CF压缩函数
            vi1 = CF(vi, b);
            vi = vi1; // 使用这样的方式来迭代
        }
        return vi1;
    }

    private static byte[] CF(byte[] vi, byte[] bi) throws IOException {
        int a,b,c,d,e,f,g,h;
        a = toInteger(vi,0);
        b = toInteger(vi,1);
        c = toInteger(vi,2);
        d = toInteger(vi,3);
        e = toInteger(vi,4);
        f = toInteger(vi,5);
        g = toInteger(vi,6);
        h = toInteger(vi,7);

        int[] w = new int[68];
        int[] w1 = new int[64];
        // bi分成了16个字
        for(int i=0;i<16;i++){
            w[i] = toInteger(bi, i);
        }
        for(int j=16;j<68;j++){
            w[j] = P1(w[j-16] ^ w[j-9] ^ Integer.rotateLeft(w[j-3], 15))^Integer.rotateLeft(w[j-13],7)^w[j-6];
        }

        for(int j=0;j<64;j++){
            w1[j] = w[j]^w[j+4];
        }

        int ss1, ss2, tt1, tt2;
        for(int j=0;j<64;j++){
            ss1 = Integer.rotateLeft(Integer.rotateLeft(a,12)+e+Integer.rotateLeft(T(j),j),7);
            ss2 = ss1^Integer.rotateLeft(a,12);
            tt1 = FF(a,b,c,j) + d + ss2 + w1[j];
            tt2 = GG(e,f,g,j) + h + ss1 + w[j];
            d = c;
            c = Integer.rotateLeft(b,9);
            b = a;
            a = tt1;
            h = g;
            g = Integer.rotateLeft(f,19);
            f = e;
            e = P0(tt2);
        }
        byte[] v = toByteArray(a,b,c,d,e,f,g,h);
        for(int i=0;i<v.length;i++){
            v[i] = (byte)(v[i]^vi[i]);
        }
        return v;
    }

    private static int toInteger(byte[] source, int index){
        StringBuilder valueStr = new StringBuilder("");
        for(int i=0;i<4;i++){
            valueStr.append(hexDigit[(byte)((source[index*4+i]&0xF0)>>4)]);
            valueStr.append(hexDigit[(byte)(source[index*4+i]&0x0F)]);
        }
        return Long.valueOf(valueStr.toString(),16).intValue();
    }

    public static byte[] toByteArray(int i){
        byte[] byteArray = new byte[4];
        byteArray[0] = (byte)(i>>>24);
        byteArray[1] = (byte)((i&0xFFFFFF)>>>16);
        byteArray[2] = (byte)((i&0xFFFF)>>>8);
        byteArray[3] = (byte)(i&0xFF);
        return byteArray;
    }

    private static byte[] toByteArray(int a,int b,int c,int d,int e,int f,int g,int h) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(32);
        baos.write(toByteArray(a));
        baos.write(toByteArray(b));
        baos.write(toByteArray(c));
        baos.write(toByteArray(d));
        baos.write(toByteArray(e));
        baos.write(toByteArray(f));
        baos.write(toByteArray(g));
        baos.write(toByteArray(h));
        return baos.toByteArray();
    }

    // byte转换称16进制字节
    private static String byteToHexString(byte b){
        int n=b;
        if(n<0){
            n+=256;
        }
        int d1 = n/16;
        int d2 = n%16;
        return ""+hexDigit[d1]+hexDigit[d2];
    }

    // byte数组转十六进制数字
    public static String byteArrayToHexString(byte[] b){
        StringBuffer sb = new StringBuffer();
        for(int i=0;i<b.length;i++){
            sb.append(byteToHexString(b[i]));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws IOException {
        String msg = "abc";

        System.out.println(SM3.byteArrayToHexString(SM3.hash("abc".getBytes())));
    }

}
