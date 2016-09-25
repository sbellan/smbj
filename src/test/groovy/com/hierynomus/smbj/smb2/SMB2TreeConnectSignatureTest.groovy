/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj.smb2

import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smbj.common.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.xml.bind.DatatypeConverter
import java.security.Security
import java.security.spec.AlgorithmParameterSpec

class SMB2TreeConnectSignatureTest extends Specification {

    def "should compute signature correctly"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
//        String hexString1 = "fe534d4240000100000000000300811f0800000000000000080000000000000000000000000000007d0000c04574000092d47c8ecdb52e0e1cb806641468b6980900000048003a005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c0049006e007300740061006c006c00";
          String hexString1 = "fe534d4240000100000000000300811f0800000000000000080000000000000000000000000000007d0000c045740000000000000000000000000000000000000900000048003a005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c0049006e007300740061006c006c00";
        String hexString2 = "fe534d4240000100000000000300c01f0800000000000000040000000000000000000000000000007d0000c045740000d05bb27ae43354cca53e17f3e1d3219c09000000480034005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c004900500043002400";
        String sessionKeyHexString = "0e8c08e8b30653d7670c726d916e584e"
        String expectedSignatureHexString1 = "92d47c8ecdb52e0e1cb806641468b698";
        String expectedSignatureHexString2 = "d05bb27ae43354cca53e17f3e1d3219c";
        byte[] dataToSign1 = DatatypeConverter.parseHexBinary(hexString1);
        byte[] dataToSign2 = DatatypeConverter.parseHexBinary(hexString2.replace("d05bb27ae43354cca53e17f3e1d3219c", "00000000000000000000000000000000"));
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature1 = DatatypeConverter.parseHexBinary(expectedSignatureHexString1);
        byte[] expectedSignature2 = DatatypeConverter.parseHexBinary(expectedSignatureHexString2);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign2);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature2))
        signature == expectedSignature2

    }

    def "should compute signature correctly self"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        String hexString1 = "fe534d424000000000000000030000010800000000000000030000000000000000000000000000004900000800600000956b39caf4794e27f436b93fd0660d9109000000480030005c005c00310030002e0031002e0032002e00320031005c0073006800610072006500640066006f006c00640065007200";
        String sessionKeyHexString = "f6770b0b89eb424b5fa08c10ea912bb2"
        String expectedSignatureHexString1 = "956b39caf4794e27f436b93fd0660d91";
        byte[] dataToSign1 = DatatypeConverter.parseHexBinary(hexString1.replace(expectedSignatureHexString1, "00000000000000000000000000000000"));
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature1 = DatatypeConverter.parseHexBinary(expectedSignatureHexString1);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign1);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature1))
        signature == expectedSignature1

    }

    def "should compute signature correctly pysmb"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        String hexString1 = "fe534d4240000000000000000300000008000000000000000300000000000000551e0100000000006900001801600000efbd3b30b451a55968766d8abd22475e09000000480022005c005c0044004300300031002d00510041005c0073006d0062007400650073007400";
        String sessionKeyHexString = "b9ee7905258cf3467659f189f24d95a2"
        String expectedSignatureHexString1 = "efbd3b30b451a55968766d8abd22475e";
        byte[] dataToSign1 = DatatypeConverter.parseHexBinary(hexString1.replace(expectedSignatureHexString1, "00000000000000000000000000000000"));
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature1 = DatatypeConverter.parseHexBinary(expectedSignatureHexString1);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign1);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature1))
        signature == expectedSignature1

    }

    def "should compute signature correctly smbclient"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        String hexString1 = "fe534d4240000100000000000300c01f0800000000000000040000000000000000000000000000007d0000c045740000d05bb27ae43354cca53e17f3e1d3219c09000000480034005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c004900500043002400";
        String sessionKeyHexString = "0e8c08e8b30653d7670c726d916e584e"
        String expectedSignatureHexString1 = "d05bb27ae43354cca53e17f3e1d3219c";
        byte[] dataToSign1 = DatatypeConverter.parseHexBinary(hexString1.replace(expectedSignatureHexString1, "00000000000000000000000000000000"));
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature1 = DatatypeConverter.parseHexBinary(expectedSignatureHexString1);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign1);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature1))
        signature == expectedSignature1

    }

    def "should compute signature correctly smbclient local"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        String hexString1 = "fe534d4240000100000000000b00a01f0800000000000000050000000000000000000000010000000d00001c01600000e74914a1f99cdfa30f886717bed512c83900000004021400ffffffffffffffffffffffffffffffff780000001c00000000000000780000000000000018000000010000000000000000000000128f0b59beb30041a4e01650f4c808370100020002021002";
        String sessionKeyHexString = "c4ed8c5c921352037eb399ec2a6d920d"
        String expectedSignatureHexString1 = "e74914a1f99cdfa30f886717bed512c8";
        byte[] dataToSign1 = DatatypeConverter.parseHexBinary(hexString1.replace(expectedSignatureHexString1, "00000000000000000000000000000000"));
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature1 = DatatypeConverter.parseHexBinary(expectedSignatureHexString1);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign1);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature1))
        signature == expectedSignature1

    }

    def "should compute same as openssl"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataToSign = "Hello".bytes
        byte[] sessionKey = DatatypeConverter.parseHexBinary("0e8c08e8b30653d7670c726d916e584e");
        byte[] expectedSignature = DatatypeConverter.parseHexBinary("42afc88e16a9750075cfd77cd4207653d1ce40cd5c995bfe1b1601198e0cd86c");

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature))
        signature == expectedSignature

    }

    // Sarvas-MBP:smbjnew saravanan$ echo -n "Hello" | openssl dgst -sha256 -hmac 04d6b077d60e323711b37813b3a68a71
    // (stdin)= cc598d8840fe409d5fcc1c1c856f9e8c311d1c458850615555857b023f1cd94c
    def "should compute same as openssl 2"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataToSign = "Hello".bytes
        byte[] sessionKey = "04d6b077d60e323711b37813b3a68a71".bytes;
        byte[] expectedSignature = DatatypeConverter.parseHexBinary("cc598d8840fe409d5fcc1c1c856f9e8c311d1c458850615555857b023f1cd94c");

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256", BouncyCastleProvider.PROVIDER_NAME)
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign);

        then:
        System.out.println(ByteArrayUtils.printHex(signature))
        System.out.println(ByteArrayUtils.printHex(expectedSignature))
        signature == expectedSignature

    }

}
