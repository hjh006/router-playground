package cn.simon.routercontrol;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import org.json.JSONObject;
import java.security.KeyStore;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Only encrypted login state is persisted; router configuration stays in memory. */
public final class SecureSession {
    private static final String ALIAS = "router-control-session-v1";
    private static final String PREFS = "private-session";

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) return (SecretKey) ks.getKey(ALIAS, null);
        KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build());
        return generator.generateKey();
    }

    public static JSONObject read(Context context) throws Exception {
        String encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("value", "");
        if (encoded.isEmpty()) return null;
        try {
            JSONObject envelope = new JSONObject(encoded);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128,
                    Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)));
            byte[] plain = cipher.doFinal(Base64.decode(envelope.getString("data"), Base64.NO_WRAP));
            return new JSONObject(new String(plain, StandardCharsets.UTF_8));
        } catch (Exception failure) {
            clear(context);
            throw new Exception("本机登录信息无法解密，请重新连接路由器。");
        }
    }

    public static void write(Context context, JSONObject session) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] data = cipher.doFinal(session.toString().getBytes(StandardCharsets.UTF_8));
        JSONObject envelope = new JSONObject();
        envelope.put("iv", Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP));
        envelope.put("data", Base64.encodeToString(data, Base64.NO_WRAP));
        if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("value", envelope.toString()).commit())
            throw new Exception("登录信息未能保存，请检查手机存储空间。");
    }

    public static void clear(Context context) throws Exception {
        if (!context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit())
            throw new Exception("登录信息未能清除，请重试。");
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
    }

    private SecureSession() {}
}
