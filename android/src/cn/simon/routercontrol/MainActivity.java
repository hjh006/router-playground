package cn.simon.routercontrol;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.webkit.CookieManager;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import org.json.JSONObject;
import java.text.DateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native controller for the router's saved AnyTLS routes. */
public final class MainActivity extends Activity {
    private static final int LOGIN = 10;
    private static final int CONTROLS = 11;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final ExecutorService cancellations = Executors.newSingleThreadExecutor();
    private final Map<String, RouteLatency> latencyResults = new LinkedHashMap<>();
    private final Set<String> expandedRegions = new LinkedHashSet<>();
    private final Set<String> queuedProbeIds = new LinkedHashSet<>();
    private boolean groupsInitialized, probeRunning;
    private volatile boolean cancelProbesRequested;
    private volatile boolean routerReadPaused, probeStartInFlight;
    private volatile String activeProbeJob = "", activeProbeNode = "";
    private String cancelBeforeStartJob = "", cancelAfterStartJob = "";
    private int probeGeneration, probeCompleted, probeTotal;
    private String probeCountry = "";
    private ConnectivityManager connectivity;
    private Network measuredNetwork;
    private final ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) {
            runOnUiThread(() -> {
                if (destroyed) return;
                boolean resumed = routerReadPaused;
                boolean changed = measuredNetwork != null && !measuredNetwork.equals(network);
                measuredNetwork = network;
                routerReadPaused = false;
                if (session != null && (resumed || changed)) {
                    feedback = probeRunning ? "手机连接已恢复，继续读取路由器测速结果…" : "手机网络已变化，路由器测速结果已保留。";
                    draw();
                }
            });
        }
        @Override public void onLost(Network network) {
            runOnUiThread(() -> {
                if (!destroyed && network.equals(measuredNetwork)) { measuredNetwork = null; pauseLatencyReads(); }
            });
        }
    };
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshTick = new Runnable() {
        @Override public void run() {
            if (destroyed) return;
            if (session != null && !busy && !probeRunning && !switchDialogOpen) refresh();
            refreshHandler.postDelayed(this, 30000);
        }
    };
    private JSONObject session;
    private RouterApi.Snapshot snapshot;
    private boolean busy, switchDialogOpen;
    private volatile boolean destroyed;
    private int generation;
    private String feedback = "";
    private String error = "";
    private long refreshedAt;
    private long healthAfterSwitch;
    private String switchedNodeId = "";
    private LinearLayout content;
    private ScrollView page;
    private int primary, surface, variant, text, muted, outline, errorColor;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        primary = getColor(R.color.primary);
        surface = getColor(R.color.surface);
        variant = getColor(R.color.surface_variant);
        text = getColor(R.color.on_surface);
        muted = getColor(R.color.on_surface_variant);
        outline = getColor(R.color.outline);
        errorColor = getColor(R.color.error);
        getWindow().setStatusBarColor(surface);
        getWindow().setNavigationBarColor(surface);
        if (Build.VERSION.SDK_INT >= 30) getWindow().setDecorFitsSystemWindows(false);
        else getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        if (state != null) {
            ArrayList<String> expanded = state.getStringArrayList("expandedRegions");
            if (expanded != null) { expandedRegions.addAll(expanded); groupsInitialized = true; }
        }
        connectivity = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivity != null) {
            try { measuredNetwork = connectivity.getActiveNetwork(); connectivity.registerDefaultNetworkCallback(networkCallback); }
            catch (Exception ignored) { /* Network-change invalidation is best effort. */ }
        }
        readSession();
        draw();
        if (session != null) refresh();
    }

    private void readSession() {
        try { session = SecureSession.read(this); }
        catch (Exception ignored) {
            session = null;
            error = "登录信息无法读取，请重新连接路由器。";
        }
    }

    private int dp(float value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private TextView label(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value); view.setTextSize(size); view.setTextColor(color);
        view.setFontFeatureSettings("kern");
        view.setLineSpacing(dp(2), 1.05f);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }
    private LinearLayout column() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.VERTICAL);
        return view;
    }
    private LinearLayout row() {
        LinearLayout view = new LinearLayout(this);
        view.setOrientation(LinearLayout.HORIZONTAL);
        view.setGravity(Gravity.CENTER_VERTICAL);
        return view;
    }
    private void gap(LinearLayout into, int height) {
        View spacer = new View(this);
        into.addView(spacer, new LinearLayout.LayoutParams(1, dp(height)));
    }
    private GradientDrawable shape(int fill, int stroke, int radius) {
        GradientDrawable background = new GradientDrawable();
        background.setColor(fill); background.setCornerRadius(dp(radius));
        if (stroke != 0) background.setStroke(dp(1), stroke);
        return background;
    }
    private Button button(String title, boolean filled, Runnable action) {
        Button button = new Button(this);
        button.setText(title); button.setTextSize(15); button.setAllCaps(false);
        button.setTextColor(filled ? getColor(R.color.on_primary) : primary);
        button.setMinHeight(dp(48)); button.setMinimumHeight(dp(48));
        button.setMinWidth(dp(72)); button.setMinimumWidth(dp(72));
        button.setPadding(dp(16), dp(10), dp(16), dp(10));
        button.setBackground(new RippleDrawable(ColorStateList.valueOf(0x3055E6CB),
                shape(filled ? primary : variant, filled ? 0 : outline, 14), null));
        button.setOnClickListener(v -> action.run());
        button.setEnabled(!busy && !probeRunning);
        if (busy || probeRunning) button.setAlpha(.45f);
        return button;
    }

    private void draw() {
        final int previousScroll = page == null ? 0 : page.getScrollY();
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(surface);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(WindowInsets.Type.systemBars()
                        | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                view.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            } else view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        ScrollView scroll = new ScrollView(this);
        page = scroll;
        scroll.setFillViewport(true); scroll.setClipToPadding(false);
        FrameLayout.LayoutParams scrollParams = new FrameLayout.LayoutParams(
                Math.min(getResources().getDisplayMetrics().widthPixels, dp(720)), -1, Gravity.TOP | Gravity.CENTER_HORIZONTAL);
        root.addView(scroll, scrollParams);
        content = column();
        content.setPadding(dp(24), dp(20), dp(24), dp(24));
        scroll.addView(content, new ScrollView.LayoutParams(-1, -2));

        LinearLayout appbar = row();
        View router = new RouterMark(this);
        appbar.addView(router, new LinearLayout.LayoutParams(dp(40), dp(40)));
        LinearLayout appTitle = column(); appTitle.setPadding(dp(14), 0, dp(4), 0);
        appTitle.addView(label("自用路由线路", 21, text, true));
        appTitle.addView(label("R7000 · ANYTLS", 12, muted, false));
        appbar.addView(appTitle, new LinearLayout.LayoutParams(0, -2, 1));
        Button settings = button("设置", false, this::settings);
        settings.setMinWidth(dp(56)); settings.setMinimumWidth(dp(56));
        settings.setPadding(dp(8), dp(10), dp(8), dp(10));
        settings.setContentDescription("路由器连接设置");
        appbar.addView(settings, new LinearLayout.LayoutParams(-2, -2));
        content.addView(appbar);
        gap(content, 26);

        if (session == null) drawWelcome();
        else drawRouter();
        gap(content, 30);
        View divider = new View(this); divider.setBackgroundColor(outline);
        content.addView(divider, new LinearLayout.LayoutParams(-1, dp(1)));
        gap(content, 14);
        TextView footer = label("路由器线路与分流控制 · 不接管手机网络", 12, muted, false);
        footer.setGravity(Gravity.CENTER);
        content.addView(footer);
        setContentView(root);
        root.requestApplyInsets();
        scroll.post(() -> scroll.scrollTo(0, previousScroll));
    }

    private void drawWelcome() {
        LinearLayout hero = column(); hero.setPadding(dp(22), dp(20), dp(22), dp(22));
        hero.setBackground(shape(variant, outline, 16));
        OrbitalView orbital = new OrbitalView(this);
        LinearLayout.LayoutParams orbitParams = new LinearLayout.LayoutParams(dp(160), dp(134));
        orbitParams.gravity = Gravity.CENTER_HORIZONTAL;
        hero.addView(orbital, orbitParams);
        hero.addView(label("连接你的路由器", 28, text, true));
        gap(hero, 10);
        hero.addView(label("登录 R7000，读取并切换已经保存的 AnyTLS 线路。", 16, muted, false));
        gap(hero, 24);
        hero.addView(button("连接路由器", true, this::openLogin), new LinearLayout.LayoutParams(-1, -2));
        content.addView(hero);
        gap(content, 22);
        content.addView(label("开始之前", 18, text, true));
        gap(content, 10);
        content.addView(label("手机需能访问路由器管理地址。连接后使用路由器自己的登录页面，登录信息仅保存在本机。", 15, muted, false));
        showError();
    }

    private void drawRouter() {
        LinearLayout hero = row(); hero.setPadding(dp(20), dp(22), dp(16), dp(22));
        hero.setBackground(shape(variant, outline, 16));
        LinearLayout summary = column();
        summary.addView(label(snapshot == null ? (busy ? "正在读取路由器" : "尚未读取路由器")
                : (error.isEmpty() ? "已连接路由器" : "路由器状态待确认"), 15, primary, true));
        gap(summary, 12);
        String name = snapshot == null ? "等待线路信息" : currentName(snapshot);
        summary.addView(label(name, 28, text, true));
        gap(summary, 8);
        summary.addView(label(snapshot == null ? "首次连接" : (snapshot.enabled ? "当前线路" : "当前线路 · 代理已关闭"), 14, muted, false));
        hero.addView(summary, new LinearLayout.LayoutParams(0, -2, 1));
        if (getResources().getConfiguration().fontScale < 1.3f
                && getResources().getConfiguration().screenWidthDp >= 360) {
            hero.addView(new OrbitalView(this), new LinearLayout.LayoutParams(dp(112), dp(124)));
        }
        content.addView(hero);
        gap(content, 12);
        content.addView(button("直连 / 代理 · 插件控制", true,
                () -> openControls("routing")), new LinearLayout.LayoutParams(-1, -2));
        gap(content, 8);
        content.addView(button("自动路由与故障切换", false,
                () -> openControls("failover")), new LinearLayout.LayoutParams(-1, -2));
        if (snapshot != null && snapshot.config.containsKey("ss_basic_failover_enable")) {
            gap(content, 8);
            content.addView(label(failoverSummary(snapshot), 14, muted, false));
        }
        gap(content, 12);
        LinearLayout health = column();
        health.setPadding(dp(18), dp(15), dp(18), dp(15));
        health.setBackground(shape(variant, outline, 14));
        TextView healthText = label("路由器 HTTPS · " + healthTitle(snapshot), 15, text, true);
        health.addView(healthText);
        gap(health, 5);
        health.addView(label(healthNote(snapshot), 13, muted, false));
        content.addView(health);
        if (busy) {
            gap(content, 16);
            LinearLayout loading = row();
            ProgressBar progress = new ProgressBar(this);
            progress.setIndeterminateTintList(ColorStateList.valueOf(primary));
            loading.addView(progress, new LinearLayout.LayoutParams(dp(24), dp(24)));
            TextView message = label(feedback.isEmpty() ? "正在读取路由器…" : feedback, 14, primary, false);
            message.setPadding(dp(12), 0, 0, 0);
            loading.addView(message, new LinearLayout.LayoutParams(0, -2, 1));
            content.addView(loading);
        } else if (!feedback.isEmpty()) {
            gap(content, 14);
            TextView status = label(feedback, 14, primary, false);
            status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
            content.addView(status);
        }
        showError();
        gap(content, 26);
        LinearLayout section = row();
        section.addView(label("国家与地区", 22, text, true), new LinearLayout.LayoutParams(0, -2, 1));
        section.addView(button("刷新", false, this::refresh), new LinearLayout.LayoutParams(-2, -2));
        content.addView(section);
        gap(content, 12);
        if (snapshot == null || snapshot.nodes.isEmpty()) {
            content.addView(label(snapshot == null ? "连接成功后显示已保存的线路。" : "没有找到已保存的 AnyTLS 线路。请先在路由器插件中添加，再点刷新。", 15, muted, false));
        } else drawGroups();
        if (refreshedAt > 0) {
            gap(content, 8);
            content.addView(label("上次读取 " + DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date(refreshedAt)), 12, muted, false));
        }
    }

    private void drawGroups() {
        Map<String, RouteGroup> groups = new LinkedHashMap<>();
        String currentGroup = "";
        for (RouterApi.Node node : snapshot.nodes) {
            CountryGroups.Region region = CountryGroups.classify(node.name);
            String key = region.code.isEmpty() ? "unknown" : region.code;
            RouteGroup group = groups.get(key);
            if (group == null) { group = new RouteGroup(key, region.flag.isEmpty() ? region.label : region.flag + " " + region.label); groups.put(key, group); }
            group.nodes.add(node);
            if (node.id.equals(snapshot.currentId)) currentGroup = key;
            RouteLatency result = latencyResults.get(node.id);
            if (result != null && !result.fingerprint.equals(RouterApi.latencyFingerprint(node, snapshot.config))) latencyResults.remove(node.id);
        }
        if (!groupsInitialized) {
            if (!currentGroup.isEmpty()) expandedRegions.add(currentGroup);
            else if (!groups.isEmpty()) expandedRegions.add(groups.keySet().iterator().next());
            groupsInitialized = true;
        }
        if (probeRunning) {
            LinearLayout progress = column();
            TextView status = label(probeCountry + " · 测速 " + probeCompleted + "/" + probeTotal, 14, primary, true);
            status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
            progress.addView(status);
            gap(progress, 6);
            progress.addView(label(routerReadPaused ? "手机连接中断，暂时暂停读取；路由器任务仍有固定时限。"
                    : "路由器逐条测节点入口 TCP，取三次成功建连的中位数，不切换当前线路。", 12, muted, false));
            gap(progress, 8);
            Button cancel = button(cancelProbesRequested ? "正在停止…" : "停止测速", false, () -> {
                requestCancelProbes();
            });
            cancel.setEnabled(!cancelProbesRequested); cancel.setAlpha(cancelProbesRequested ? .45f : 1f);
            progress.addView(cancel, new LinearLayout.LayoutParams(-1, -2));
            content.addView(progress); gap(content, 14);
        }
        List<RouteGroup> ordered = new ArrayList<>(groups.values());
        if (!currentGroup.isEmpty()) {
            RouteGroup selected = groups.get(currentGroup);
            ordered.remove(selected); ordered.add(0, selected);
        }
        for (RouteGroup group : ordered) drawGroup(group);
        gap(content, 4);
        content.addView(label("点“测延迟”仅测本组。入口 TCP 为路由器到节点入口三次成功建连的中位数；路径待确认时不显示数值。完整代理连通性另看上方 HTTPS 检测，超过 5 分钟请重测。", 12, muted, false));
    }

    private void drawGroup(RouteGroup group) {
        boolean expanded = expandedRegions.contains(group.key);
        LinearLayout block = column();
        LinearLayout header = row();
        Button toggle = button(group.title + " · " + group.nodes.size() + " 条线路 · " + (expanded ? "收起" : "展开"), false, () -> {
            if (expandedRegions.contains(group.key)) expandedRegions.remove(group.key);
            else expandedRegions.add(group.key);
            draw();
        });
        // Folding is safe during an ongoing probe or refresh; it never writes to the router.
        toggle.setEnabled(true); toggle.setAlpha(1f); toggle.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        toggle.setContentDescription(group.title + "，" + group.nodes.size() + "条线路，" + (expanded ? "已展开，点按收起" : "已收起，点按展开"));
        header.addView(toggle, new LinearLayout.LayoutParams(0, -2, 1));
        block.addView(header);
        if (expanded) {
            gap(block, 8);
            Button measure = button("测延迟", false, () -> measureGroup(group));
            measure.setContentDescription("测量路由器到" + group.title + "节点入口的 TCP 延迟");
            block.addView(measure, new LinearLayout.LayoutParams(-1, -2));
            gap(block, 10);
            boolean twoColumns = getResources().getConfiguration().screenWidthDp >= 360
                    && getResources().getConfiguration().fontScale < 1.3f;
            for (int i = 0; i < group.nodes.size(); i += twoColumns ? 2 : 1) {
                LinearLayout line = row();
                line.setGravity(Gravity.TOP); line.setBaselineAligned(false);
                line.addView(routeCard(group.nodes.get(i)), new LinearLayout.LayoutParams(0, -2, 1));
                if (twoColumns) {
                    View space = new View(this); line.addView(space, new LinearLayout.LayoutParams(dp(12), 1));
                    if (i + 1 < group.nodes.size()) line.addView(routeCard(group.nodes.get(i + 1)), new LinearLayout.LayoutParams(0, -2, 1));
                    else line.addView(new View(this), new LinearLayout.LayoutParams(0, 1, 1));
                }
                block.addView(line, new LinearLayout.LayoutParams(-1, -2));
                gap(block, 10);
            }
        }
        content.addView(block, new LinearLayout.LayoutParams(-1, -2));
        gap(content, 14);
    }

    private LinearLayout routeCard(RouterApi.Node node) {
        boolean selected = node.id.equals(snapshot.currentId);
        LinearLayout item = column();
        item.setPadding(dp(14), dp(14), dp(14), dp(12));
        item.setBackground(shape(selected ? getColor(R.color.primary_container) : variant, selected ? primary : outline, 16));
        String routeName = node.name.isEmpty() ? "未命名线路" : node.name;
        String flag = CountryGroups.classify(node.name).flag;
        if (!flag.isEmpty() && !CountryGroups.hasFlag(routeName)) routeName = flag + " " + routeName;
        item.addView(label(routeName, 16, text, true));
        gap(item, 10);
        RouteLatency result = latencyResults.get(node.id);
        boolean expired = result != null && SystemClock.elapsedRealtime() - result.receivedAtMillis > 300000;
        String latency = "未测";
        if (queuedProbeIds.contains(node.id)) latency = node.id.equals(activeProbeNode)
                ? (routerReadPaused ? "等待读取…" : "测量中…") : "排队中…";
        else if (result != null) {
            if ("ok".equals(result.status)) latency = result.latencyMs + " ms";
            else if ("timeout".equals(result.status)) latency = "超时";
            else if ("dns_failed".equals(result.status)) latency = "解析失败";
            else if ("path_unverified".equals(result.status)) latency = "路径待确认";
            else if ("unsupported_node".equals(result.reason)) latency = "暂不支持";
            else if ("invalid_settings".equals(result.reason) || "invalid_hosts".equals(result.reason)) latency = "设置待核对";
            else latency = "检测失败";
            if (expired) latency += " · 已过期";
        }
        item.addView(label("入口 TCP · " + latency, 12,
                result != null && "ok".equals(result.status) && !expired && !queuedProbeIds.contains(node.id) ? primary : muted, false));
        if (result != null && !queuedProbeIds.contains(node.id)) {
            gap(item, 3);
            item.addView(label((result.checkedAtMillis > 0 ? "路由器测于 " : "读取于 ")
                    + DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date(result.checkedAtMillis > 0 ? result.checkedAtMillis : result.receivedWallClockMillis))
                    + (expired ? " · 请重测" : ""), 12, muted, false));
        }
        View spacer = new View(this); item.addView(spacer, new LinearLayout.LayoutParams(1, 0, 1));
        gap(item, 12);
        if (selected) {
            TextView active = label("使用中", 14, primary, true);
            active.setGravity(Gravity.CENTER); active.setMinHeight(dp(48));
            item.addView(active, new LinearLayout.LayoutParams(-1, -2));
        } else {
            Button change = button("切换", false, () -> confirmSwitch(node));
            change.setContentDescription("切换到" + node.name);
            item.addView(change, new LinearLayout.LayoutParams(-1, -2));
        }
        return item;
    }

    private void measureGroup(RouteGroup group) {
        if (busy || probeRunning || snapshot == null || switchDialogOpen) return;
        final Map<String, String> config = new LinkedHashMap<>(snapshot.config);
        final List<RouterApi.Node> nodes = new ArrayList<>(group.nodes);
        probeRunning = true; cancelProbesRequested = false; probeCompleted = 0;
        probeTotal = nodes.size(); probeCountry = group.title; error = ""; feedback = "";
        queuedProbeIds.clear(); for (RouterApi.Node node : nodes) queuedProbeIds.add(node.id);
        final int token = ++probeGeneration;
        draw();
        worker.execute(() -> {
            try {
                RouterApi connection = api();
                if (!connection.supportsRouterLatency()) throw new IOException("未检测到兼容的路由器入口 TCP 测速组件。请确认登录，或安装仅测速组件后再试。");
                String outcome = probeCountry + " 的入口 TCP 延迟测量已完成。";
                for (RouterApi.Node node : nodes) {
                    if (destroyed || Thread.currentThread().isInterrupted()) return;
                    if (cancelProbesRequested) { outcome = "本组后续测速已停止，已完成结果保留。"; break; }
                    if (routerReadPaused) throw new IOException("手机连接暂时不可用，已保留完成结果；重新连接后再读取或测量。");
                    final String jobId = UUID.randomUUID().toString().replace("-", "");
                    activeProbeJob = jobId; activeProbeNode = node.id; probeStartInFlight = true;
                    probeUi(token, this::draw);
                    final long deadline = SystemClock.elapsedRealtime() + 40000;
                    try {
                        // A failed response can still mean the router started this nonce. Never resubmit.
                        connection.startLatency(node.id, jobId);
                    } catch (IOException ignored) {
                        // Resolve an uncertain submission only by reading the matching job below.
                    } finally {
                        probeStartInFlight = false;
                        if (cancelProbesRequested && !destroyed) cancelLatencyJob(jobId, true);
                    }
                    if (destroyed || Thread.currentThread().isInterrupted()) return;
                    final long graceUntil = SystemClock.elapsedRealtime() + 3000;
                    RouterApi.LatencyJob completed = null;
                    while (SystemClock.elapsedRealtime() < deadline) {
                        if (destroyed || Thread.currentThread().isInterrupted()) return;
                        if (routerReadPaused) { Thread.sleep(1000); continue; }
                        RouterApi.LatencyJob state;
                        try { state = connection.readLatency(); }
                        catch (IOException failure) {
                            throw new IOException(cancelProbesRequested
                                    ? "停止请求尚未确认，路由器任务可能仍在完成；请恢复连接后核对。"
                                    : (failure.getMessage() == null ? "无法读取路由器测速状态。" : failure.getMessage() + "。")
                                        + " 任务可能已提交，请检查连接后再试，不要连续重复启动。");
                        }
                        if (jobId.equals(state.jobId) && node.id.equals(state.nodeId)) {
                            if (state.isTerminal()) { completed = state; break; }
                        } else if (SystemClock.elapsedRealtime() >= graceUntil) {
                            if ("running".equals(state.state)) throw new IOException("路由器正在执行其他测速，本组已停止，请稍后再试。");
                            // Legacy firmware may acknowledge the POST before preparing the job.
                            // An old idle/terminal snapshot is not a failure of this new nonce.
                        }
                        Thread.sleep(1000);
                    }
                    if (completed == null) throw new IOException(cancelProbesRequested
                            ? "停止请求尚未确认，路由器会按任务时限结束；已完成结果保留。"
                            : "本次测速结果尚未读到，路由器任务有固定时限；请重新连接后核对，已完成结果保留。");
                    if ("busy".equals(completed.state)) throw new IOException("路由器正在执行其他测速，本组已停止，请稍后再试。");
                    if ("changed".equals(completed.state)) {
                        probeUi(token, () -> latencyResults.remove(node.id));
                        throw new IOException("线路配置已变化，请刷新线路列表后重新测速。");
                    }
                    if ("cancelled".equals(completed.state)) { outcome = "路由器已确认当前测速取消，已完成结果保留。"; break; }
                    final RouteLatency result = new RouteLatency(completed, RouterApi.latencyFingerprint(node, config));
                    probeUi(token, () -> {
                        queuedProbeIds.remove(node.id); latencyResults.put(node.id, result); probeCompleted++;
                        draw();
                    });
                    activeProbeJob = ""; activeProbeNode = "";
                    if (cancelProbesRequested) { outcome = "当前测速已结束，本组后续测速已停止，已完成结果保留。"; break; }
                }
                final String finished = outcome;
                probeUi(token, () -> {
                    probeRunning = false; queuedProbeIds.clear(); feedback = finished;
                    draw();
                });
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            catch (Exception failure) {
                final String reason = failure instanceof IOException && failure.getMessage() != null
                        ? failure.getMessage() : "无法确认测速结果，请检查路由器连接后再试。";
                probeUi(token, () -> { probeRunning = false; queuedProbeIds.clear(); feedback = ""; error = reason; draw(); });
            } finally {
                activeProbeJob = ""; activeProbeNode = ""; probeStartInFlight = false;
            }
        });
    }
    private void requestCancelProbes() {
        if (!probeRunning || cancelProbesRequested) return;
        cancelProbesRequested = true;
        feedback = "正在请求停止本组测速，等待路由器确认；已完成结果保留。";
        cancelLatencyJob(activeProbeJob, !probeStartInFlight); draw();
    }
    private void cancelLatencyJob(String jobId, boolean afterStart) {
        if (jobId.isEmpty() || destroyed) return;
        synchronized (this) {
            if (afterStart) { if (jobId.equals(cancelAfterStartJob)) return; cancelAfterStartJob = jobId; }
            else { if (jobId.equals(cancelBeforeStartJob) || jobId.equals(cancelAfterStartJob)) return; cancelBeforeStartJob = jobId; }
        }
        // Cancellation uses a separate connection so a slow start/poll cannot block the stop button.
        try {
            cancellations.execute(() -> {
                try { api().cancelLatency(jobId); }
                catch (Exception ignored) {
                    runOnUiThread(() -> {
                        if (!destroyed && probeRunning && cancelProbesRequested && jobId.equals(activeProbeJob)) {
                            feedback = "停止请求尚未确认，正在读取路由器状态；任务仍有固定时限。"; draw();
                        }
                    });
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException ignored) { /* Activity already destroyed; the router keeps its hard time limit. */ }
    }
    private void probeUi(int token, Runnable action) {
        runOnUiThread(() -> { if (!destroyed && token == probeGeneration) action.run(); });
    }
    private void pauseLatencyReads() {
        routerReadPaused = true;
        if (session != null) { feedback = "手机连接已断开，已完成的路由器测速结果保留；重新连接后继续读取。"; draw(); }
    }
    private static final class RouteGroup {
        final String key, title;
        final List<RouterApi.Node> nodes = new ArrayList<>();
        RouteGroup(String key, String title) { this.key = key; this.title = title; }
    }
    private static final class RouteLatency {
        final String status, fingerprint, reason;
        final long latencyMs, checkedAtMillis;
        final long receivedAtMillis = SystemClock.elapsedRealtime();
        final long receivedWallClockMillis = System.currentTimeMillis();
        RouteLatency(RouterApi.LatencyJob result, String fingerprint) {
            status = result.state; reason = result.reason; latencyMs = result.latencyMs; checkedAtMillis = result.checkedAtMillis;
            this.fingerprint = fingerprint;
        }
    }

    private String currentName(RouterApi.Snapshot value) {
        for (RouterApi.Node node : value.nodes) if (node.id.equals(value.currentId)) return node.name;
        return "当前为其他协议线路";
    }
    private boolean freshHealth(RouterApi.Snapshot value) {
        if (value == null || value.health == null) return false;
        if (value.failover != null && ("direct".equals(value.failover.optString("mode"))
                || "error".equals(value.failover.optString("mode")))) return false;
        JSONObject health = value.health;
        long checked = health.optLong("checked_at", 0);
        long age = System.currentTimeMillis() / 1000 - checked;
        long interval = Math.max(1, health.optLong("interval_sec", 30));
        return health.optInt("version", 0) == 1 && checked > 0
                && (!value.currentId.equals(switchedNodeId) || checked >= healthAfterSwitch)
                && value.currentId.equals(health.optString("node_id"))
                && age >= -300 && age <= Math.max(90, interval * 3)
                && (health.optBoolean("enabled", false) || "1".equals(health.optString("enabled")));
    }
    private String healthTitle(RouterApi.Snapshot value) {
        if (value == null) return "等待读取";
        if (!value.enabled) return "代理已关闭";
        if (value.failover != null && "direct".equals(value.failover.optString("mode"))) return "故障直连保护 · 代理检测暂停";
        if (value.failover != null && "error".equals(value.failover.optString("mode"))) return "当前网络路径待确认";
        if (value.health == null) return "暂无检测数据";
        if (!value.currentId.equals(value.health.optString("node_id"))) return "等待当前线路检测";
        if (!freshHealth(value)) return "检测数据已过期";
        String state = value.health.optString("status");
        if ("healthy".equals(state)) return "最近检测已连通";
        if ("degraded".equals(state)) return "连接有波动";
        if ("down".equals(state)) return "最近检测未通过";
        return "正在检测";
    }
    private String healthNote(RouterApi.Snapshot value) {
        if (value == null) return "结果来自路由器的 HTTPS 检测。";
        if (!value.enabled) return "切换会保存线路，代理开关保持关闭。";
        if (!freshHealth(value)) return "当前连通性未知，点刷新读取最新结果。";
        long total = value.health.optLong("total", -1), success = value.health.optLong("success", -1);
        String note = total >= 0 && success >= 0 && success <= total ? "短期采样 " + success + "/" + total + " 轮通过" : "最近一次路由器采样";
        long checked = value.health.optLong("checked_at", 0);
        double latency = value.health.optDouble("last_latency_ms", Double.NaN);
        String measured = !Double.isNaN(latency) && !Double.isInfinite(latency) && latency >= 0
                ? " · " + Math.round(latency) + " ms" : "";
        return note + measured + " · " + DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date(checked * 1000));
    }
    private void showError() {
        if (error.isEmpty()) return;
        gap(content, 16);
        TextView message = label(error, 14, errorColor, false);
        message.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_ASSERTIVE);
        content.addView(message);
        if (session != null) {
            gap(content, 8);
            content.addView(button("重新登录", false, this::openLogin), new LinearLayout.LayoutParams(-1, -2));
        }
    }

    private RouterApi api() throws Exception {
        return new RouterApi(session.getString("baseUrl"), session.optString("cookie"), session.optString("basicAuth"));
    }
    private String failoverSummary(RouterApi.Snapshot value) {
        if (!value.enabled) return "当前路径：直连 · 代理已手动关闭";
        if (!"1".equals(value.config.get("ss_basic_failover_enable"))) return "自动故障切换：关闭";
        JSONObject state = value.failover;
        if (state == null) return "自动故障切换：状态待确认";
        long age = System.currentTimeMillis() / 1000 - state.optLong("checked_at", 0);
        if (age < -300 || age > 240) return "自动故障切换：状态已过期，请刷新核对";
        if (!value.currentId.equals(state.optString("current_node"))) return "自动故障切换：等待当前线路状态";
        if ("error".equals(state.optString("mode")) || "error".equals(state.optString("state")))
            return "自动故障切换：网络路径恢复待确认";
        if ("direct".equals(state.optString("mode"))) return "当前路径：故障直连保护 · 后台继续寻找可用线路";
        switch (state.optString("state")) {
            case "healthy": return "当前路径：代理 · 自动故障切换待命";
            case "confirming": return "自动路由：正在确认线路故障";
            case "scanning_proxy": case "scanning_direct":
                return "自动路由：正在检测备用线路 · " + state.optInt("scanned", 0) + " / " + state.optInt("total", 0);
            case "recovering": return "自动路由：候选线路恢复确认中";
            case "cooldown": return "自动路由：切换冷却中";
            case "switched": return "自动路由：已切换备用线路";
            default: return "自动故障切换：等待新状态";
        }
    }
    private void openControls(String group) {
        if (busy || probeRunning || session == null) return;
        startActivityForResult(new Intent(this, PluginSettingsActivity.class).putExtra("group", group), CONTROLS);
    }
    private void refresh() {
        if (busy || probeRunning || session == null) return;
        busy = true; error = ""; feedback = "正在读取路由器…";
        final int token = ++generation;
        draw();
        worker.execute(() -> {
            try {
                RouterApi connection = api();
                RouterApi.Snapshot result = connection.load();
                for (int i = 0; i < 3 && result.enabled && !freshHealth(result); i++) {
                    final RouterApi.Snapshot pending = result;
                    ui(token, () -> { snapshot = pending; feedback = "正在等待路由器的 HTTPS 检测…"; draw(); });
                    Thread.sleep(2000);
                    result = connection.load();
                }
                final RouterApi.Snapshot loaded = result;
                ui(token, () -> { snapshot = loaded; refreshedAt = System.currentTimeMillis(); busy = false; feedback = ""; draw(); });
            } catch (Exception ignored) {
                ui(token, () -> { busy = false; feedback = "";
                    error = "无法读取路由器。请确认手机能访问管理地址、登录未过期，然后刷新或重新登录。"; draw(); });
            }
        });
    }
    private void confirmSwitch(RouterApi.Node node) {
        if (busy || probeRunning || snapshot == null) return;
        switchDialogOpen = true;
        new AlertDialog.Builder(this).setTitle("切换到“" + node.name + "”？")
                .setMessage(snapshot.enabled ? "路由器将应用这条线路，网络可能短暂中断。" : "代理当前关闭。本次仅保存线路，代理开关仍保持关闭。")
                .setNegativeButton("取消", null).setPositiveButton("切换线路", (dialog, which) -> switchRoute(node))
                .setOnDismissListener(dialog -> switchDialogOpen = false).show();
    }
    private void switchRoute(RouterApi.Node node) {
        if (busy || probeRunning) return;
        busy = true; error = ""; feedback = "正在应用线路，请稍候…";
        healthAfterSwitch = System.currentTimeMillis() / 1000;
        switchedNodeId = node.id;
        final int token = ++generation;
        draw();
        worker.execute(() -> {
            RouterApi.Snapshot latest = null;
            boolean configured = false;
            try {
                RouterApi connection = api();
                connection.switchNode(node.id);
                for (int i = 0; i < 6; i++) {
                    if (Thread.currentThread().isInterrupted()) return;
                    Thread.sleep(3000);
                    try { latest = connection.load(); }
                    catch (Exception ignored) { continue; }
                    configured = node.id.equals(latest.currentId);
                    final RouterApi.Snapshot progress = latest;
                    if (configured) {
                        ui(token, () -> { snapshot = progress; refreshedAt = System.currentTimeMillis();
                            feedback = progress.enabled ? "配置已切换，等待 HTTPS 检测…" : "线路已保存，代理保持关闭。"; draw(); });
                        if (!latest.enabled || (freshHealth(latest) && "healthy".equals(latest.health.optString("status")))) break;
                    }
                }
                final RouterApi.Snapshot result = latest;
                final boolean confirmed = configured;
                ui(token, () -> {
                    if (result != null) { snapshot = result; refreshedAt = System.currentTimeMillis(); }
                    busy = false;
                    if (confirmed) feedback = result.enabled ? (freshHealth(result) && "healthy".equals(result.health.optString("status"))
                            ? "线路已切换，最近 HTTPS 检测已连通。" : "线路配置已切换，HTTPS 连通性尚未确认。") : "线路已保存，代理保持关闭。";
                    else { feedback = ""; error = "尚未确认线路切换结果。请稍后刷新，确认当前线路后再操作。"; }
                    draw();
                });
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            catch (Exception ignored) {
                ui(token, () -> { busy = false; feedback = "";
                    error = "未能确认应用结果。请求可能已到达路由器，请先刷新核对当前线路，避免重复提交。"; draw(); });
            }
        });
    }
    private void ui(int token, Runnable action) {
        runOnUiThread(() -> { if (!destroyed && token == generation) action.run(); });
    }
    private void openLogin() {
        if (busy || probeRunning) return;
        Intent intent = new Intent(this, LoginActivity.class);
        if (session != null) intent.putExtra("baseUrl", session.optString("baseUrl"));
        startActivityForResult(intent, LOGIN);
    }
    private void settings() {
        if (busy || probeRunning) return;
        if (session == null) { openLogin(); return; }
        new AlertDialog.Builder(this).setTitle("设置与管理")
                .setItems(new String[]{"插件功能与分流设置", "原插件完整面板", "管理地址 / 重新登录", "清除本机登录信息", "关于"}, (dialog, which) -> {
                    if (which == 0) openControls("routing");
                    else if (which == 1) startActivityForResult(new Intent(this, PluginPanelActivity.class), CONTROLS);
                    else if (which == 2) openLogin();
                    else if (which == 3) new AlertDialog.Builder(this).setTitle("清除登录信息？")
                            .setMessage("将移除 App 保存的登录信息，路由器继续按当前线路运行。")
                            .setNegativeButton("取消", null).setPositiveButton("清除", (d, w) -> forget()).show();
                    else new AlertDialog.Builder(this).setTitle("自用路由线路 1.4.0")
                            .setMessage("个人 R7000 AnyTLS 路由控制器\n\n线路、直连与代理、设备分流、自动故障切换、广告过滤及高级连接设置。完整插件面板提供其他功能。手机不创建 VPN。\n\nUI 和图标依据 ImageGen 设计实现。线路按国家与地区归类。入口 TCP 延迟由路由器采样，取三次成功建连的中位数，只对已验证路径显示数值，不切换当前线路。完整代理连通性由独立 HTTPS 检测展示。")
                            .setPositiveButton("知道了", null).show();
                }).show();
    }
    private void forget() {
        try {
            SecureSession.clear(this);
            CookieManager.getInstance().removeAllCookies(null);
            CookieManager.getInstance().flush();
            session = null; snapshot = null; refreshedAt = 0; feedback = ""; error = ""; generation++;
            healthAfterSwitch = 0; switchedNodeId = "";
            latencyResults.clear(); expandedRegions.clear(); groupsInitialized = false; probeGeneration++;
        } catch (Exception ignored) { error = "无法清除登录信息，请关闭 App 后重试。"; }
        draw();
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == LOGIN && resultCode == RESULT_OK) {
            generation++; snapshot = null; refreshedAt = 0; error = ""; feedback = "";
            healthAfterSwitch = 0; switchedNodeId = "";
            latencyResults.clear(); expandedRegions.clear(); groupsInitialized = false; probeGeneration++;
            readSession(); draw(); if (session != null) refresh();
        } else if (requestCode == CONTROLS) {
            // Controls and the embedded original panel may change routing or the active node.
            healthAfterSwitch = 0; switchedNodeId = "";
            cancelProbesRequested = true; latencyResults.clear();
            readSession();
            if (session != null) refresh();
        }
    }
    @Override protected void onResume() {
        super.onResume();
        refreshHandler.removeCallbacks(refreshTick);
        refreshHandler.postDelayed(refreshTick, 30000);
        if (session != null && !busy && !probeRunning && System.currentTimeMillis() - refreshedAt > 30000) refresh();
    }
    @Override protected void onPause() {
        refreshHandler.removeCallbacks(refreshTick);
        super.onPause();
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state);
        state.putStringArrayList("expandedRegions", new ArrayList<>(expandedRegions));
    }
    @Override protected void onDestroy() {
        destroyed = true; generation++; probeGeneration++; cancelProbesRequested = true;
        refreshHandler.removeCallbacks(refreshTick); worker.shutdownNow(); cancellations.shutdown();
        if (connectivity != null) try { connectivity.unregisterNetworkCallback(networkCallback); } catch (Exception ignored) {}
        super.onDestroy();
    }

    private final class RouterMark extends View {
        private final Paint paint = new Paint(3);
        RouterMark(android.content.Context context) { super(context); setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO); }
        @Override protected void onDraw(Canvas c) {
            paint.setColor(primary); paint.setStrokeWidth(dp(1.7f)); paint.setStyle(Paint.Style.STROKE);
            float w = getWidth(), h = getHeight();
            c.drawRoundRect(w * .08f, h * .45f, w * .92f, h * .85f, dp(5), dp(5), paint);
            c.drawLine(w * .24f, h * .44f, w * .19f, h * .12f, paint);
            c.drawLine(w * .75f, h * .44f, w * .80f, h * .12f, paint);
            paint.setStyle(Paint.Style.FILL);
            for (int i = 0; i < 3; i++) c.drawCircle(w * (.54f + .11f * i), h * .65f, dp(1.3f), paint);
        }
    }
}
