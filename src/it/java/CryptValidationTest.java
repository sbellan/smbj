import com.hierynomus.ntlm.functions.NtlmFunctions;
import com.hierynomus.protocol.commons.ByteArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.Security;

/**
 * Created by saravanan on 9/24/16.
 */
public class CryptValidationTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // [MS_NLMP] 4.2

    // U.s.e.r.
    byte[] CONST_U_s_e_r = DatatypeConverter.parseHexBinary("55 00 73 00 65 00 72 00".replaceAll(" ", ""));
    // U.S.E.R.
    byte[] CONST_U_S_E_R = DatatypeConverter.parseHexBinary("55 00 53 00 45 00 52 00".replaceAll(" ", ""));
    // User
    byte[] CONST_User = DatatypeConverter.parseHexBinary("55 73 65 72".replaceAll(" ", ""));

    // D.o.m.a.i.n.
    byte[] CONST_UserDom = DatatypeConverter.parseHexBinary("44 00 6f 00 6d 00 61 00 69 00 6e 00".replaceAll(" ", ""));

    // P.a.s.s.w.o.r.d.
    byte[] CONST_P_a_s_s_w_o_r_d = DatatypeConverter.parseHexBinary("50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00".replaceAll(" ", ""));
    // PASSWORD......
    byte[] CONST_PASSWORD = DatatypeConverter.parseHexBinary("50 41 53 53 57 4f 52 44 00 00 00 00 00 00".replaceAll(" ", ""));

    // S.e.r.v.e.r.
    byte[] CONST_S_e_r_v_e_r = DatatypeConverter.parseHexBinary("53 00 65 00 72 00 76 00 65 00 72 00".replaceAll(" ", ""));

    // C.O.M.P.U.T.E.R.
    byte[] CONST_Wkstation_Name = DatatypeConverter.parseHexBinary("43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00".replaceAll(" ", ""));

    // UUUUUUUUUUUUUUUU
    byte[] CONST_Random_SessionKey = DatatypeConverter.parseHexBinary("55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55".replaceAll(" ", ""));

    byte[] CONST_Time = DatatypeConverter.parseHexBinary("00 00 00 00 00 00 00 00".replaceAll(" ", ""));

    // ........
    byte[] CONST_ClientChallenge = DatatypeConverter.parseHexBinary("aa aa aa aa aa aa aa aa".replaceAll(" ", ""));

    // .#Eg..&#x2550;.
    byte[] CONST_ServerChallenge = DatatypeConverter.parseHexBinary("01 23 45 67 89 ab cd ef".replaceAll(" ", ""));

    @Test
    public void testCrypt() {

        byte[] bytes = NtlmFunctions.NTOWFv2("Password", "User", "Domain");
        System.out.println(ByteArrayUtils.printHex(bytes));
    }
}
