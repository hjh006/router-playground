package cn.simon.routercontrol;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Build;
import android.text.InputType;
import android.util.Base64;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebStorage;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Firmware login stays same-origin. No Javascript bridge or credential scraping. */
public final class LoginActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private LinearLayout root;
    private EditText address;
    private TextView feedback;
    private WebView web;
    private ProgressBar progress;
    private String base = "", basic = "";
    private boolean checking, alive = true;
    private int generation;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        if (Build.VERSION.SDK_INT >= 30) getWindow().setDecorFitsSystemWindows(false);
        else getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        base = state == null ? getIntent().getStringExtra("baseUrl") : state.getString("routerAddress", "");
        if (base == null) base = "";
        showAddress();
    }

    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private int color(int id) { return getColor(id); }
    private TextView text(String value, int size, int color) {
        TextView v = new TextView(this); v.setText(value); v.setTextSize(size); v.setTextColor(color);
        v.setPadding(0, dp(8), 0, dp(8)); return v;
    }
    private Button button(String label, View.OnClickListener action) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setMinHeight(dp(48));
        b.setTextColor(color(R.color.on_primary));
        b.setBackgroundTintList(ColorStateList.valueOf(color(R.color.primary)));
        b.setOnClickListener(action); return b;
    }
    private void shell() {
        root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(color(R.color.surface)); root.setPadding(dp(24), dp(8), dp(24), dp(12));
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                v.setPadding(dp(24) + safe.left, dp(8) + safe.top, dp(24) + safe.right, dp(12) + safe.bottom);
            } else v.setPadding(dp(24) + insets.getSystemWindowInsetLeft(), dp(8) + insets.getSystemWindowInsetTop(),
                    dp(24) + insets.getSystemWindowInsetRight(), dp(12) + insets.getSystemWindowInsetBottom());
            return insets;
        });
        setContentView(root); root.requestApplyInsets();
    }
    private void showAddress() {
        generation++; checking = false;
        if (web != null) { web.stopLoading(); web.clearCache(true); web.destroy(); web = null; }
        shell();
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true);
        LinearLayout content = new LinearLayout(this); content.setOrientation(LinearLayout.VERTICAL);
        scroll.addView(content); root.addView(scroll, new LinearLayout.LayoutParams(-1, -1));
        content.addView(text("连接路由器", 28, color(R.color.on_surface)));
        content.addView(text("连接家中 Wi-Fi，填写路由器的管理地址。", 16, color(R.color.on_surface_variant)));
        content.addView(text("管理地址", 14, color(R.color.on_surface)));
        address = new EditText(this); address.setSingleLine(true);
        address.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        address.setHint("http://路由器 IP 或 https://管理域名");
        address.setTextColor(color(R.color.on_surface)); address.setHintTextColor(color(R.color.on_surface_variant));
        address.setMinHeight(dp(56)); address.setText(base);
        address.setId(View.generateViewId());
        content.addView(address, new LinearLayout.LayoutParams(-1, -2));
        feedback = text("", 14, color(R.color.error)); feedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        content.addView(feedback);
        content.addView(button("打开路由器登录", v -> connect()), new LinearLayout.LayoutParams(-1, -2));
        content.addView(text("使用路由器管理账号登录。登录信息经 Android Keystore 加密后仅保存在本机，可在 App 中退出登录清除。", 14, color(R.color.on_surface_variant)));
        content.addView(text("旧固件使用 HTTP 时，请在可信的家庭网络操作。HTTPS 使用系统证书校验，不会忽略证书错误。", 14, color(R.color.on_surface_variant)));
        content.addView(button("返回", v -> finish()), new LinearLayout.LayoutParams(-1, -2));
        try { JSONObject saved = SecureSession.read(this); if (base.isEmpty() && saved != null) address.setText(saved.optString("baseUrl")); }
        catch (Exception ignored) { feedback.setText("登录信息已失效，请重新连接。"); }
    }
    private void connect() {
        final String proposed = address.getText().toString().trim();
        if (proposed.isEmpty()) { address.setError("请填写管理地址"); address.requestFocus(); return; }
        feedback.setText("正在检查地址…");
        final int token = ++generation;
        worker.execute(() -> {
            try {
                final String valid = RouterApi.validateBaseUrl(proposed);
                runOnUiThread(() -> { if (alive && generation == token) { base = valid; basic = ""; showLogin(); } });
            } catch (Exception e) {
                runOnUiThread(() -> { if (alive && generation == token) { address.setError("地址不可用；请填写局域网 HTTP 或有效 HTTPS 管理地址。"); feedback.setText("请检查地址格式、Wi-Fi 和路由器是否在线。"); } });
            }
        });
    }
    private void showLogin() {
        ((InputMethodManager)getSystemService(INPUT_METHOD_SERVICE)).hideSoftInputFromWindow(address.getWindowToken(), 0);
        shell();
        root.addView(text("路由器登录", 22, color(R.color.on_surface)));
        root.addView(text(base, 13, color(R.color.on_surface_variant)));
        feedback = text("在下方完成固件登录，再点击“读取线路”。", 14, color(R.color.on_surface_variant));
        feedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); root.addView(feedback);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setIndeterminate(true); root.addView(progress, new LinearLayout.LayoutParams(-1, dp(4)));
        web = new WebView(this);
        web.setBackgroundColor(Color.WHITE);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setCacheMode(android.webkit.WebSettings.LOAD_NO_CACHE);
        web.getSettings().setAllowFileAccess(false);
        web.getSettings().setAllowContentAccess(false);
        web.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.getSettings().setSupportMultipleWindows(false);
        web.getSettings().setSaveFormData(false);
        web.getSettings().setBuiltInZoomControls(true);
        web.getSettings().setDisplayZoomControls(false);
        web.getSettings().setUseWideViewPort(true);
        web.getSettings().setLoadWithOverviewMode(true);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        WebView.setWebContentsDebuggingEnabled(false);
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onConsoleMessage(ConsoleMessage message) { return true; }
        });
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest request) {
                if (!sameOrigin(request.getUrl().toString())) { feedback.setText("已阻止离开当前路由器的链接。"); return true; }
                return false;
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView v, WebResourceRequest request) {
                if (sameOrigin(request.getUrl().toString())) return null;
                return new WebResourceResponse("text/plain", "UTF-8", new ByteArrayInputStream(new byte[0]));
            }
            @Override public void onPageFinished(WebView v, String url) {
                if (alive && sameOrigin(url)) { progress.setVisibility(View.GONE); probe(false); }
            }
            @Override public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) {
                handler.cancel(); feedback.setText("HTTPS 证书校验失败。请使用可信证书，或在家庭 Wi-Fi 使用路由器的 HTTP 地址。");
            }
            @Override public void onReceivedError(WebView v, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) { progress.setVisibility(View.GONE); feedback.setText("无法打开路由器，请检查 Wi-Fi、管理地址和端口。"); }
            }
            @Override public void onReceivedHttpAuthRequest(WebView v, HttpAuthHandler handler, String host, String realm) {
                if (!Uri.parse(base).getHost().equalsIgnoreCase(host)) { handler.cancel(); return; }
                basicDialog(handler);
            }
        });
        root.addView(web, new LinearLayout.LayoutParams(-1, 0, 1));
        root.addView(button("读取线路", v -> probe(true)), new LinearLayout.LayoutParams(-1, -2));
        Button back = button("更改管理地址", v -> showAddress());
        root.addView(back, new LinearLayout.LayoutParams(-1, -2));
        CookieManager.getInstance().removeAllCookies(removed -> {
            CookieManager.getInstance().flush();
            if (alive && web != null) web.loadUrl(base + "/Main_Login.asp");
        });
    }
    private boolean sameOrigin(String candidate) {
        try {
            Uri a = Uri.parse(base), b = Uri.parse(candidate);
            int ap = a.getPort() < 0 ? ("https".equals(a.getScheme()) ? 443 : 80) : a.getPort();
            int bp = b.getPort() < 0 ? ("https".equals(b.getScheme()) ? 443 : 80) : b.getPort();
            return a.getScheme().equals(b.getScheme()) && a.getHost().equalsIgnoreCase(b.getHost()) && ap == bp && b.getUserInfo() == null;
        } catch (Exception e) { return false; }
    }
    private void basicDialog(HttpAuthHandler handler) {
        LinearLayout form = new LinearLayout(this); form.setPadding(dp(24), dp(8), dp(24), 0); form.setOrientation(LinearLayout.VERTICAL);
        form.addView(text("管理账号", 14, color(R.color.on_surface)));
        EditText user = new EditText(this); user.setSingleLine(true); user.setMinHeight(dp(48)); user.setAutofillHints(View.AUTOFILL_HINT_USERNAME); form.addView(user);
        form.addView(text("管理密码", 14, color(R.color.on_surface)));
        EditText pass = new EditText(this); pass.setSingleLine(true); pass.setMinHeight(dp(48));
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD); pass.setAutofillHints(View.AUTOFILL_HINT_PASSWORD); form.addView(pass);
        new AlertDialog.Builder(this).setTitle("登录此路由器").setView(form)
                .setNegativeButton("取消", (d, w) -> handler.cancel())
                .setOnCancelListener(d -> handler.cancel())
                .setPositiveButton("登录", (d, w) -> {
                    String u = user.getText().toString(), p = pass.getText().toString();
                    basic = "Basic " + Base64.encodeToString((u + ":" + p).getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
                    handler.proceed(u, p);
                }).show();
    }
    private void probe(boolean explicit) {
        if (checking || !alive) return;
        checking = true;
        final int token = generation;
        final String target = base, auth = basic;
        final String cookie = CookieManager.getInstance().getCookie(base + "/");
        if (explicit) { feedback.setText("正在读取已保存线路…"); progress.setVisibility(View.VISIBLE); }
        worker.execute(() -> {
            try {
                new RouterApi(target, cookie == null ? "" : cookie, auth).load();
                runOnUiThread(() -> {
                    if (!alive || generation != token) return;
                    try {
                        JSONObject s = new JSONObject(); s.put("baseUrl", target); s.put("cookie", cookie == null ? "" : cookie); s.put("basicAuth", auth);
                        SecureSession.write(this, s);
                        CookieManager.getInstance().removeAllCookies(removed -> CookieManager.getInstance().flush());
                        setResult(RESULT_OK); finish();
                    } catch (Exception ignored) { checking = false; feedback.setText("无法安全保存登录信息，请重试。"); progress.setVisibility(View.GONE); }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    if (!alive || generation != token) return;
                    checking = false; progress.setVisibility(View.GONE);
                    if (explicit) feedback.setText("尚未读取到插件配置。请完成登录，确认已安装 R7000 AnyTLS 增强插件后重试。");
                });
            }
        });
    }
    @Override protected void onSaveInstanceState(Bundle out) {
        out.putString("routerAddress", web == null && address != null ? address.getText().toString() : base);
        super.onSaveInstanceState(out);
    }
    @Override protected void onDestroy() {
        alive = false; generation++; worker.shutdownNow();
        if (web != null) { web.stopLoading(); web.clearCache(true); web.clearFormData(); web.destroy(); web = null; }
        WebStorage.getInstance().deleteAllData();
        CookieManager.getInstance().removeAllCookies(removed -> CookieManager.getInstance().flush());
        super.onDestroy();
    }
}
