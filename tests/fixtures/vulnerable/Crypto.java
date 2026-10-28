import javax.crypto.Cipher;
class Crypto {
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding"); // expect: SV-CRY-003
    String q = "SELECT * FROM t WHERE id = " + id; // expect: SV-INJ-001
}
