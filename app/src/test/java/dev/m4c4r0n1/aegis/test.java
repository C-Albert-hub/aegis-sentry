package dev.m4c4r0n1.aegis;

import java.util.Base64;

public class test {
    public static void main(String[] args) {
        String text = "吾爱破解论坛";
        // 编码
        String encodedString = Base64.getEncoder().encodeToString(text.getBytes());
        System.out.println("Encoded string: " + encodedString);

        // 解码
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
        String decodedString = new String(decodedBytes);
        System.out.println("Decoded string: " + decodedString);

    }
}
