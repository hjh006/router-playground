package cn.simon.routercontrol;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.webkit.ConsoleMessage;
import android.webkit.CookieManager;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebStorage;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.ValueCallback;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

/** Original same-origin plugin UI for the complete set of legacy controls. No native JS bridge. */
public final class PluginPanelActivity extends Activity {
    private WebView web;
    private TextView feedback;
    private ProgressBar progress;
    private String base = "", basic = "";
    private boolean alive = true;
    private ValueCallback<Uri[]> upload;
    private boolean exportChoosing, exporting;
    private final ExecutorService files = Executors.newSingleThreadExecutor();

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(getColor(R.color.surface)); getWindow().setNavigationBarColor(getColor(R.color.surface));
        if (Build.VERSION.SDK_INT >= 30) getWindow().setDecorFitsSystemWindows(false);
        else getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(getColor(R.color.surface)); root.setSaveFromParentEnabled(false);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                v.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            } else v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        LinearLayout bar = new LinearLayout(this); bar.setOrientation(LinearLayout.HORIZONTAL); bar.setPadding(dp(12), dp(8), dp(12), dp(8));
        bar.addView(button("返回 App", () -> finish()), new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(button("刷新面板", () -> { if (web != null) web.reload(); }), new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(button("重新登录", () -> startActivityForResult(new Intent(this, LoginActivity.class).putExtra("baseUrl", base), 10)), new LinearLayout.LayoutParams(0, -2, 1));
        root.addView(bar);
        feedback = new TextView(this); feedback.setTextSize(13); feedback.setTextColor(getColor(R.color.on_surface_variant));
        feedback.setPadding(dp(16), dp(2), dp(16), dp(10));
        feedback.setText("原插件完整面板 · 更改会直接应用到路由器，可双指缩放。");
        feedback.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); root.addView(feedback);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setIndeterminate(true);
        progress.setIndeterminateTintList(ColorStateList.valueOf(getColor(R.color.primary))); root.addView(progress, new LinearLayout.LayoutParams(-1, dp(3)));
        setContentView(root); root.requestApplyInsets();
        try {
            JSONObject session = SecureSession.read(this);
            if (session == null) throw new IllegalStateException();
            base = RouterApi.validateBaseUrl(session.getString("baseUrl")); basic = session.optString("basicAuth");
            web = new WebView(this); web.setSaveEnabled(false); web.setSaveFromParentEnabled(false); web.setBackgroundColor(Color.WHITE);
            web.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            WebSettings settings = web.getSettings(); settings.setJavaScriptEnabled(true); settings.setDomStorageEnabled(true);
            settings.setCacheMode(WebSettings.LOAD_NO_CACHE); settings.setAllowFileAccess(false); settings.setAllowContentAccess(false);
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW); settings.setSupportMultipleWindows(false);
            settings.setSaveFormData(false); settings.setBuiltInZoomControls(true); settings.setDisplayZoomControls(false);
            settings.setUseWideViewPort(true); settings.setLoadWithOverviewMode(true); settings.setMediaPlaybackRequiresUserGesture(true);
            WebView.setWebContentsDebuggingEnabled(false);
            CookieManager cookies = CookieManager.getInstance(); cookies.setAcceptCookie(true); cookies.setAcceptThirdPartyCookies(web, false);
            web.setWebChromeClient(new WebChromeClient() {
                @Override public boolean onConsoleMessage(ConsoleMessage message) { return true; }
                @Override public void onProgressChanged(WebView view, int value) { if (alive) progress.setVisibility(value < 100 ? View.VISIBLE : View.GONE); }
                @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams parameters) {
                    if (!pluginPage(view.getUrl()) || parameters.getMode() != FileChooserParams.MODE_OPEN || parameters.isCaptureEnabled()) {
                        callback.onReceiveValue(null); return true;
                    }
                    if (upload != null) upload.onReceiveValue(null);
                    upload = callback;
                    new AlertDialog.Builder(PluginPanelActivity.this).setTitle("导入路由器配置？")
                            .setMessage("请选择可信的插件备份文件。原插件恢复配置可能替换现有线路和设置，请先保留当前备份。文件仅交给当前路由器页面。")
                            .setNegativeButton("取消", (d, w) -> finishUpload(null))
                            .setOnCancelListener(d -> finishUpload(null))
                            .setPositiveButton("选择备份文件", (d, w) -> {
                                try {
                                    Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
                                    picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                                    startActivityForResult(picker, 30);
                                } catch (ActivityNotFoundException ignored) { finishUpload(null); feedback.setText("没有可用的系统文件选择器。"); }
                            }).show();
                    return true;
                }
            });
            web.setWebViewClient(new WebViewClient() {
                @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                    if (request.isForMainFrame() && backupUrl(request.getUrl())) { chooseExport(); return true; }
                    if (sameOrigin(request.getUrl())) return false;
                    if (request.isForMainFrame() && request.hasGesture()) openExternal(request.getUrl());
                    return true;
                }
                @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                    if (sameOrigin(request.getUrl())) return null;
                    return new WebResourceResponse("text/plain", "UTF-8", new ByteArrayInputStream(new byte[0]));
                }
                @Override public void onPageFinished(WebView view, String url) {
                    if (!alive) return;
                    progress.setVisibility(View.GONE);
                    if (sameOrigin(Uri.parse(url)) && "/Main_Login.asp".equalsIgnoreCase(Uri.parse(url).getPath())) {
                        feedback.setText("登录已过期，请返回 App 首页重新登录后打开面板。");
                    }
                }
                @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                    handler.cancel(); feedback.setText("HTTPS 证书校验失败，请返回首页核对管理地址和证书。");
                }
                @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                    if (request.isForMainFrame()) { progress.setVisibility(View.GONE); feedback.setText("面板加载失败，请检查连接后刷新，或返回首页重新登录。"); }
                }
                @Override public void onReceivedHttpAuthRequest(WebView view, HttpAuthHandler handler, String host, String realm) {
                    try {
                        if (!sameOrigin(Uri.parse(view.getUrl())) || !Uri.parse(base).getHost().equalsIgnoreCase(host)
                                || !basic.startsWith("Basic ")) throw new IllegalArgumentException();
                        String decoded = new String(android.util.Base64.decode(basic.substring(6), android.util.Base64.DEFAULT), StandardCharsets.UTF_8);
                        int split = decoded.indexOf(':'); if (split < 0) throw new IllegalArgumentException();
                        handler.proceed(decoded.substring(0, split), decoded.substring(split + 1));
                    } catch (Exception ignored) { handler.cancel(); feedback.setText("登录已过期，请返回 App 首页重新登录。"); }
                }
            });
            web.setDownloadListener((url, userAgent, disposition, mime, length) -> {
                if (backupUrl(Uri.parse(url))) chooseExport();
                else feedback.setText("此下载不属于插件配置备份，请使用浏览器操作。");
            });
            root.addView(web, new LinearLayout.LayoutParams(-1, 0, 1));
            Map<String, String> headers = new HashMap<>(); if (!basic.isEmpty()) headers.put("Authorization", basic);
            List<String> savedCookies = new ArrayList<>();
            for (String cookie : session.optString("cookie").split(";")) if (cookie.contains("=")) savedCookies.add(cookie.trim());
            if (savedCookies.isEmpty()) web.loadUrl(base + "/Main_Ss_Content.asp", headers);
            else {
                AtomicInteger remaining = new AtomicInteger(savedCookies.size());
                for (String cookie : savedCookies) cookies.setCookie(base, cookie + "; Path=/", accepted -> {
                    if (remaining.decrementAndGet() == 0 && alive && web != null) {
                        cookies.flush(); web.loadUrl(base + "/Main_Ss_Content.asp", headers);
                    }
                });
            }
        } catch (Exception ignored) { progress.setVisibility(View.GONE); feedback.setText("登录信息无法读取，请返回 App 首页重新连接路由器。"); }
    }
    private int dp(int n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private Button button(String label, Runnable action) {
        Button b = new Button(this); b.setText(label); b.setTextSize(14); b.setAllCaps(false); b.setMinHeight(dp(48));
        b.setTextColor(getColor(R.color.primary)); b.setBackgroundTintList(ColorStateList.valueOf(getColor(R.color.surface_variant)));
        b.setOnClickListener(v -> action.run()); return b;
    }
    private boolean sameOrigin(Uri candidate) {
        try {
            Uri expected = Uri.parse(base); int ep = expected.getPort() < 0 ? ("https".equals(expected.getScheme()) ? 443 : 80) : expected.getPort();
            int cp = candidate.getPort() < 0 ? ("https".equals(candidate.getScheme()) ? 443 : 80) : candidate.getPort();
            return expected.getScheme().equals(candidate.getScheme()) && expected.getHost().equalsIgnoreCase(candidate.getHost())
                    && ep == cp && candidate.getUserInfo() == null;
        } catch (Exception ignored) { return false; }
    }
    private void openExternal(Uri url) {
        if (!("https".equals(url.getScheme()) || "http".equals(url.getScheme()))) { feedback.setText("已阻止不支持的外部链接。"); return; }
        try { startActivity(new Intent(Intent.ACTION_VIEW, url)); }
        catch (ActivityNotFoundException ignored) { feedback.setText("没有可打开此链接的浏览器。"); }
    }
    private boolean pluginPage(String url) {
        if (url == null) return false;
        Uri candidate = Uri.parse(url);
        return sameOrigin(candidate) && "/Main_Ss_Content.asp".equals(candidate.getPath());
    }
    private boolean backupUrl(Uri candidate) {
        return sameOrigin(candidate) && "/ss_conf_backup.txt".equals(candidate.getEncodedPath())
                && candidate.getQuery() == null && candidate.getFragment() == null;
    }
    private void finishUpload(Uri uri) {
        ValueCallback<Uri[]> callback = upload; upload = null;
        if (callback != null) callback.onReceiveValue(uri == null ? null : new Uri[]{uri});
    }
    private void chooseExport() {
        if (!alive || exportChoosing || exporting || web == null || web.getUrl() == null || !sameOrigin(Uri.parse(web.getUrl()))) return;
        exportChoosing = true;
        new AlertDialog.Builder(this).setTitle("导出路由器配置？")
                .setMessage("备份可能包含线路密码、设备与其他私有设置。请选择自己保管的保存位置。App 只导出路由器的插件备份，不上传或留存副本。")
                .setNegativeButton("取消", (d, w) -> exportChoosing = false)
                .setOnCancelListener(d -> exportChoosing = false)
                .setPositiveButton("选择保存位置", (d, w) -> {
                    try {
                        Intent picker = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("text/plain");
                        picker.putExtra(Intent.EXTRA_TITLE, "ss_conf_backup.txt"); picker.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
                        startActivityForResult(picker, 31);
                    } catch (ActivityNotFoundException ignored) { exportChoosing = false; feedback.setText("没有可用的系统文件选择器。"); }
                }).show();
    }
    private void exportTo(Uri destination) {
        exporting = true; feedback.setText("正在导出插件备份…");
        files.execute(() -> {
            byte[] privateData = null; boolean saved = false;
            try {
                JSONObject session = SecureSession.read(this);
                if (session == null) throw new IOException();
                RouterApi connection = new RouterApi(session.getString("baseUrl"), session.optString("cookie"), session.optString("basicAuth"));
                privateData = connection.exportBackup();
                try (OutputStream output = getContentResolver().openOutputStream(destination, "wt")) {
                    if (output == null) throw new IOException(); output.write(privateData); output.flush();
                }
                saved = true;
            } catch (Exception ignored) { /* Never expose backup contents or document-provider errors. */ }
            finally { if (privateData != null) Arrays.fill(privateData, (byte) 0); }
            final boolean completed = saved;
            runOnUiThread(() -> {
                exporting = false;
                if (alive) feedback.setText(completed ? "插件备份已导出到所选位置，请妥善保管。" : "未能完成导出，请检查路由器登录与保存位置；所选文件可能为空或不完整。" );
            });
        });
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 10 && resultCode == RESULT_OK) { setResult(RESULT_OK); recreate(); }
        else if (requestCode == 30) {
            Uri selected = resultCode == RESULT_OK && data != null ? data.getData() : null;
            if (selected != null && (!"content".equals(selected.getScheme()) || !pluginPage(web == null ? null : web.getUrl()))) selected = null;
            finishUpload(selected);
        } else if (requestCode == 31) {
            exportChoosing = false;
            Uri destination = resultCode == RESULT_OK && data != null ? data.getData() : null;
            if (destination != null && "content".equals(destination.getScheme())) exportTo(destination);
        }
    }
    @Override public void onBackPressed() { if (web != null && web.canGoBack()) web.goBack(); else finish(); }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state); state.clear(); // Never persist the router DOM, URLs or form fields.
    }
    @Override protected void onDestroy() {
        alive = false;
        finishUpload(null); files.shutdown();
        if (web != null) { web.stopLoading(); web.clearCache(true); web.clearHistory(); web.destroy(); web = null; }
        WebStorage.getInstance().deleteAllData(); super.onDestroy();
    }
}
