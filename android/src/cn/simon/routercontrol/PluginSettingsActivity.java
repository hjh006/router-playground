package cn.simon.routercontrol;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

/** Native, independently saved plugin controls. Private drafts never enter saved-instance state. */
public final class PluginSettingsActivity extends Activity {
    private static final String[] GROUPS = {"routing", "devices", "failover", "adblock", "acl", "dns", "health", "anytls"};
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler pendingHandler = new Handler(Looper.getMainLooper());
    private final Map<String, Control> controls = new LinkedHashMap<>();
    private Memory memory;
    private JSONObject session;
    private Map<String, String> formBase;
    private LinearLayout content;
    private ScrollView scroll;
    private boolean busy, alive = true;
    private int generation;
    private String feedback = "", error = "";
    private int primary, surface, variant, text, muted, outline, errorColor;

    private static final class Memory {
        RouterApi.Snapshot snapshot;
        String group = "routing";
        final Map<String, Map<String, String>> drafts = new LinkedHashMap<>();
        final Map<String, Map<String, String>> bases = new LinkedHashMap<>();
        boolean pending;
        volatile boolean mutationInFlight;
        String pendingGroup;
        Map<String, String> pendingDesired;
    }

    private static final class Control {
        final PluginSettings.Field field;
        final View view;
        final String initial;
        final List<String> options;
        Control(PluginSettings.Field field, View view, String initial, List<String> options) {
            this.field = field; this.view = view; this.initial = initial; this.options = options;
        }
        String value() {
            return view instanceof EditText ? ((EditText) view).getText().toString()
                    : options.get(((Spinner) view).getSelectedItemPosition());
        }
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE);
        primary = getColor(R.color.primary); surface = getColor(R.color.surface);
        variant = getColor(R.color.surface_variant); text = getColor(R.color.on_surface);
        muted = getColor(R.color.on_surface_variant); outline = getColor(R.color.outline); errorColor = getColor(R.color.error);
        getWindow().setStatusBarColor(surface); getWindow().setNavigationBarColor(surface);
        if (Build.VERSION.SDK_INT >= 30) getWindow().setDecorFitsSystemWindows(false);
        else getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION);
        Object retained = getLastNonConfigurationInstance();
        memory = retained instanceof Memory ? (Memory) retained : new Memory();
        if (retained == null && Arrays.asList(GROUPS).contains(getIntent().getStringExtra("group"))) {
            memory.group = getIntent().getStringExtra("group");
        }
        try { session = SecureSession.read(this); }
        catch (Exception ignored) { error = "登录信息无法读取，请返回首页重新登录。"; }
        if (memory.pending) feedback = "上次操作结果待核对，正在重新读取；不会重复提交。";
        if (memory.mutationInFlight) { busy = true; feedback = "设置仍在提交或核对中，请稍候；不会重复提交。"; }
        draw();
        if (memory.mutationInFlight) waitForMutation();
        else if (session != null && (memory.snapshot == null || memory.pending)) refresh(false);
    }

    private int dp(float n) { return Math.round(n * getResources().getDisplayMetrics().density); }
    private LinearLayout column() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.VERTICAL); return v; }
    private LinearLayout row() { LinearLayout v = new LinearLayout(this); v.setOrientation(LinearLayout.HORIZONTAL); v.setGravity(Gravity.CENTER_VERTICAL); return v; }
    private TextView label(String value, int size, int color, boolean bold) {
        TextView v = new TextView(this); v.setText(value); v.setTextSize(size); v.setTextColor(color);
        v.setLineSpacing(dp(2), 1.05f); if (bold) v.setTypeface(Typeface.DEFAULT, Typeface.BOLD); return v;
    }
    private void gap(LinearLayout into, int height) { into.addView(new View(this), new LinearLayout.LayoutParams(1, dp(height))); }
    private GradientDrawable shape(int fill, int border, int radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(fill); d.setCornerRadius(dp(radius));
        if (border != 0) d.setStroke(dp(1), border); return d;
    }
    private Button button(String title, boolean filled, Runnable action) {
        Button b = new Button(this); b.setText(title); b.setTextSize(15); b.setAllCaps(false);
        b.setMinHeight(dp(48)); b.setMinimumHeight(dp(48)); b.setMinWidth(dp(64)); b.setMinimumWidth(dp(64));
        b.setPadding(dp(14), dp(10), dp(14), dp(10));
        b.setTextColor(filled ? getColor(R.color.on_primary) : primary);
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x3055E6CB), shape(filled ? primary : variant, filled ? 0 : outline, 14), null));
        b.setOnClickListener(v -> action.run()); b.setEnabled(!busy); if (busy) b.setAlpha(.5f); return b;
    }

    private void draw() {
        controls.clear();
        FrameLayout root = new FrameLayout(this); root.setBackgroundColor(surface); root.setSaveFromParentEnabled(false);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets safe = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
                v.setPadding(safe.left, safe.top, safe.right, safe.bottom);
            } else v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        scroll = new ScrollView(this); scroll.setFillViewport(true);
        root.addView(scroll, new FrameLayout.LayoutParams(Math.min(getResources().getDisplayMetrics().widthPixels, dp(760)), -1, Gravity.TOP | Gravity.CENTER_HORIZONTAL));
        content = column(); content.setPadding(dp(24), dp(20), dp(24), dp(32));
        scroll.addView(content, new ScrollView.LayoutParams(-1, -2));
        LinearLayout bar = row();
        bar.addView(button("返回", false, this::leave), new LinearLayout.LayoutParams(-2, -2));
        TextView title = label("插件控制", 22, text, true); title.setPadding(dp(16), 0, 0, 0);
        bar.addView(title, new LinearLayout.LayoutParams(0, -2, 1)); content.addView(bar); gap(content, 20);
        content.addView(label("选择网络走向，管理路由器功能。", 15, muted, false)); gap(content, 14);
        Spinner categories = new Spinner(this); categories.setSaveEnabled(false); categories.setMinimumHeight(dp(52));
        List<String> titles = new ArrayList<>(); for (String group : GROUPS) titles.add(PluginSettings.title(group));
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, titles);
        categories.setAdapter(adapter); categories.setSelection(Arrays.asList(GROUPS).indexOf(memory.group));
        categories.setContentDescription("插件功能分类"); categories.setEnabled(!busy);
        content.addView(categories, new LinearLayout.LayoutParams(-1, -2));
        categories.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onNothingSelected(AdapterView<?> parent) {}
            @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (view instanceof TextView) ((TextView) view).setTextColor(text);
                String selected = GROUPS[position];
                if (!selected.equals(memory.group)) { stash(); memory.group = selected; feedback = ""; error = ""; draw(); }
            }
        });
        gap(content, 20);
        if (busy) {
            ProgressBar progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
            progress.setIndeterminate(true); progress.setIndeterminateTintList(ColorStateList.valueOf(primary));
            content.addView(progress, new LinearLayout.LayoutParams(-1, dp(4))); gap(content, 12);
        }
        TextView result = label(error.isEmpty() ? feedback : error, 14, error.isEmpty() ? muted : errorColor, false);
        result.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        if (!error.isEmpty() || !feedback.isEmpty()) { content.addView(result); gap(content, 16); }
        if (memory.snapshot != null) {
            content.addView(label(memory.snapshot.version + " · " + (memory.snapshot.enabled ? "代理开关已开启" : "代理开关已关闭"), 13, muted, false)); gap(content, 16);
            status();
            content.addView(label(PluginSettings.title(memory.group), 24, text, true)); gap(content, 8);
            content.addView(label(PluginSettings.description(memory.group), 14, muted, false)); gap(content, 22);
            if (!PluginSettings.supported(memory.group, memory.snapshot.config)) {
                content.addView(label("当前插件未提供这组兼容字段。请更新插件或使用原插件面板核对。", 15, errorColor, false));
            } else {
                formBase = memory.bases.getOrDefault(memory.group, memory.snapshot.config);
                for (PluginSettings.Field field : PluginSettings.fields(memory.group, formBase)) addField(field);
                gap(content, 10);
                content.addView(button("保存" + PluginSettings.title(memory.group), true, this::confirmSave), new LinearLayout.LayoutParams(-1, -2));
                gap(content, 10);
                content.addView(label("仅提交这一页修改的项目。" + ("adblock".equals(memory.group) ? "广告设置会热更新，不重启代理或 UU。" : "应用时代理和 DNS 可能短暂重载；UU 仍由原插件管理。"), 13, muted, false));
            }
        } else if (!busy) content.addView(label("读取配置后，这里会显示路由器当前设置。", 16, muted, false));
        gap(content, 26);
        content.addView(button("刷新路由器状态", false, () -> refresh(true)), new LinearLayout.LayoutParams(-1, -2));
        gap(content, 10);
        content.addView(button("打开原插件完整面板", false, this::openPanel), new LinearLayout.LayoutParams(-1, -2));
        gap(content, 10);
        content.addView(label("节点管理、规则、日志及其他原有功能可在完整面板中操作。订阅和规则自动更新保持现有关闭设置。", 13, muted, false));
        setContentView(root); root.requestApplyInsets();
    }

    private void addField(PluginSettings.Field field) {
        String initial = PluginSettings.value(field, formBase);
        String value = memory.drafts.getOrDefault(memory.group, new LinkedHashMap<>()).getOrDefault(field.key, initial);
        TextView name = label(field.label, 16, text, true); content.addView(name); gap(content, 7);
        View input;
        List<String> values = null;
        if (field.values != null && field.values.length > 0) {
            Spinner spinner = new Spinner(this); spinner.setMinimumHeight(dp(52));
            values = new ArrayList<>(Arrays.asList(field.values));
            List<String> labels = new ArrayList<>(Arrays.asList(field.labels));
            if (!values.contains(value)) { values.add(value); labels.add("当前值（插件扩展）"); }
            ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels);
            spinner.setAdapter(adapter); spinner.setSelection(values.indexOf(value));
            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                @Override public void onNothingSelected(AdapterView<?> parent) {}
                @Override public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                    if (view instanceof TextView) ((TextView) view).setTextColor(text);
                }
            });
            input = spinner;
        } else {
            EditText editor = new EditText(this); editor.setTextColor(text); editor.setHintTextColor(muted);
            editor.setTextSize(16); editor.setMinHeight(dp(52)); editor.setPadding(dp(12), dp(12), dp(12), dp(12));
            editor.setBackgroundTintList(ColorStateList.valueOf(outline)); editor.setText(value);
            editor.setSingleLine(!field.multiline);
            editor.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                    | (field.multiline ? InputType.TYPE_TEXT_FLAG_MULTI_LINE : 0));
            editor.setAutofillHints((String[]) null); editor.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
            editor.setFreezesText(false); if (field.multiline) { editor.setMinLines(3); editor.setMaxLines(8); editor.setGravity(Gravity.TOP); }
            input = editor;
        }
        input.setId(View.generateViewId()); name.setLabelFor(input.getId()); input.setContentDescription(field.label);
        input.setSaveEnabled(false); input.setSaveFromParentEnabled(false); input.setEnabled(!busy);
        if (busy) input.setAlpha(.5f);
        content.addView(input, new LinearLayout.LayoutParams(-1, -2));
        if (field.help != null && !field.help.isEmpty()) { gap(content, 6); content.addView(label(field.help, 13, muted, false)); }
        if ("ss_basic_failover_nodes".equals(field.key)) {
            gap(content, 8); content.addView(button("查看线路 ID 对照", false, this::showNodeCatalog), new LinearLayout.LayoutParams(-1, -2));
        }
        gap(content, 22); controls.put(field.key, new Control(field, input, initial, values));
    }

    private void showNodeCatalog() {
        if (busy || memory.snapshot == null) return;
        LinearLayout list = column(); list.setPadding(dp(20), dp(8), dp(20), dp(8));
        list.addView(label("候选 ID 留空表示全部有效 AnyTLS 线路。展开国家或地区查看 ID；分类来自线路名称。", 14, muted, false)); gap(list, 16);
        Map<String, List<RouterApi.Node>> grouped = new LinkedHashMap<>();
        for (RouterApi.Node node : memory.snapshot.nodes) {
            CountryGroups.Region country = CountryGroups.classify(node.name);
            String key = country.flag.isEmpty() ? country.label : country.flag + " " + country.label;
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(node);
        }
        for (Map.Entry<String, List<RouterApi.Node>> entry : grouped.entrySet()) {
            LinearLayout rows = column(); rows.setVisibility(View.GONE);
            Button heading = button(entry.getKey() + " · " + entry.getValue().size() + " 条 · 展开", false, () -> {});
            heading.setOnClickListener(v -> {
                boolean expand = rows.getVisibility() != View.VISIBLE;
                rows.setVisibility(expand ? View.VISIBLE : View.GONE);
                heading.setText(entry.getKey() + " · " + entry.getValue().size() + " 条 · " + (expand ? "收起" : "展开"));
            });
            list.addView(heading, new LinearLayout.LayoutParams(-1, -2));
            for (RouterApi.Node node : entry.getValue()) {
                TextView line = label("ID " + node.id + "   " + node.name, 15, text, false);
                line.setPadding(dp(6), dp(12), dp(6), dp(12)); rows.addView(line);
            }
            list.addView(rows); gap(list, 10);
        }
        if (grouped.isEmpty()) list.addView(label("尚未读取到有效 AnyTLS 线路，请返回后刷新。", 15, muted, false));
        ScrollView catalog = new ScrollView(this); catalog.addView(list); catalog.setSaveEnabled(false);
        AlertDialog dialog = new AlertDialog.Builder(this).setTitle("线路 ID 对照").setView(catalog).setPositiveButton("关闭", null).create();
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE); dialog.show();
        dialog.getWindow().setLayout(-1, Math.min(dp(600), getResources().getDisplayMetrics().heightPixels * 4 / 5));
    }

    private void status() {
        JSONObject data = "failover".equals(memory.group) || "routing".equals(memory.group) ? memory.snapshot.failover
                : "adblock".equals(memory.group) ? memory.snapshot.adblock : null;
        if (data == null) return;
        String summary;
        if ("adblock".equals(memory.group)) {
            String state = data.optString("state");
            if (data.optInt("version") != 1) summary = "广告过滤运行状态待确认";
            else if ("error".equals(state)) summary = "广告设置未成功应用，请查看插件日志。";
            else if ((!memory.snapshot.enabled || !"1".equals(memory.snapshot.config.get("ss_basic_adblock_enable"))) && "active".equals(state)) summary = "广告过滤配置已关闭或代理暂停，读取时运行状态待刷新。";
            else if ("draining".equals(state)) summary = "等待旧 DNS 连接释放，当前先保持兼容直通。";
            else if ("active".equals(state) && data.optBoolean("enabled") && data.optBoolean("running")) summary = "读取时广告过滤运行中 · 有效域名 " + data.optInt("domains") + " · 排除设备 " + data.optInt("excluded_devices");
            else summary = "广告过滤已关闭或暂停" + (data.optBoolean("running") ? "，兼容转发正在等待旧连接释放。" : "。");
        } else if (!memory.snapshot.enabled) summary = "当前选择直连，自动切换不会重新开启手动关闭的代理。";
        else if (!"1".equals(memory.snapshot.config.get("ss_basic_failover_enable"))) summary = "自动故障切换未开启";
        else {
            long now = System.currentTimeMillis() / 1000, checked = data.optLong("checked_at");
            String mode = data.optString("mode"), state = data.optString("state");
            if (data.optInt("version") != 1 || checked <= 0) summary = "自动切换运行状态待确认";
            else if (now - checked > 240 || checked - now > 300) summary = "自动切换状态已过期，请刷新后核对。";
            else if (!memory.snapshot.currentId.equals(data.optString("current_node"))) summary = "正在等待当前线路的自动切换状态。";
            else if ("error".equals(mode) || "error".equals(state)) summary = "网络路径恢复待确认，请查看插件日志。";
            else if ("direct".equals(mode)) summary = "直连保护中 · 后台继续检测备用线路";
            else {
                Map<String, String> labels = new LinkedHashMap<>();
                labels.put("healthy", "当前线路可用"); labels.put("confirming", "正在确认线路故障");
                labels.put("scanning_direct", "直连保护 · 检测候选中"); labels.put("scanning_proxy", "正在检测备用线路");
                labels.put("recovering", "候选线路恢复确认中"); labels.put("direct", "直连保护中");
                labels.put("switched", "已切换备用线路"); labels.put("cooldown", "切换冷却中"); labels.put("disabled", "自动故障切换已停止");
                summary = labels.getOrDefault(state, "自动切换运行状态待确认");
            }
            int scanned = data.optInt("scanned", -1), total = data.optInt("total", -1);
            if (checked > 0 && now - checked <= 240 && checked - now <= 300 && memory.snapshot.currentId.equals(data.optString("current_node")) && scanned >= 0 && total >= scanned && total <= 128) summary += " · 已检测 " + scanned + "/" + total;
        }
        LinearLayout state = column(); state.setPadding(dp(16), dp(14), dp(16), dp(14)); state.setBackground(shape(variant, outline, 14));
        state.addView(label(summary, 14, text, false)); content.addView(state); gap(content, 24);
    }

    private Map<String, String> values() {
        Map<String, String> values = new LinkedHashMap<>();
        for (Control control : controls.values()) values.put(control.field.key, control.value());
        return values;
    }
    private Map<String, String> changes() {
        Map<String, String> changes = new LinkedHashMap<>();
        for (Control control : controls.values()) if (!control.value().equals(control.initial)) changes.put(control.field.key, control.value());
        return changes;
    }
    private void stash() {
        if (controls.isEmpty() || formBase == null) return;
        if (changes().isEmpty()) { memory.drafts.remove(memory.group); memory.bases.remove(memory.group); }
        else { memory.drafts.put(memory.group, values()); memory.bases.put(memory.group, new LinkedHashMap<>(formBase)); }
    }
    private boolean dirty() { stash(); return !memory.drafts.isEmpty(); }
    private RouterApi api() throws Exception {
        JSONObject saved = SecureSession.read(this);
        if (saved == null) throw new IOException("登录信息已失效，请返回首页重新登录。");
        return new RouterApi(saved.getString("baseUrl"), saved.optString("cookie"), saved.optString("basicAuth"));
    }
    private void refresh(boolean ask) {
        if (busy) return;
        if (memory.mutationInFlight) { busy = true; draw(); waitForMutation(); return; }
        if (ask && dirty()) {
            new AlertDialog.Builder(this).setTitle("刷新并放弃未保存修改？")
                    .setMessage("将重新读取路由器配置。尚未保存的页面修改会被清除。")
                    .setNegativeButton("继续编辑", null).setPositiveButton("刷新", (d, w) -> {
                        memory.drafts.clear(); memory.bases.clear(); controls.clear(); formBase = null; refresh(false);
                    }).show();
            return;
        }
        stash(); busy = true; error = ""; feedback = "正在读取配置和运行状态…"; draw(); final int token = ++generation;
        worker.execute(() -> {
            try {
                RouterApi.Snapshot loaded = api().load();
                ui(token, () -> {
                    memory.snapshot = loaded; memory.pending = false; busy = false;
                    feedback = "已读取路由器配置。";
                    if (memory.pendingDesired != null) {
                        if (matches(memory.pendingDesired, loaded.config)) {
                            memory.drafts.remove(memory.pendingGroup); memory.bases.remove(memory.pendingGroup);
                            feedback = "上次保存的配置已读取确认；实际运行情况请结合状态与设备访问核对。";
                        } else feedback = "上次保存结果未确认，已读取当前配置。请先核对，再决定是否重新保存。";
                        memory.pendingDesired = null; memory.pendingGroup = null;
                    }
                    draw();
                });
            } catch (Exception ignored) {
                ui(token, () -> { busy = false; feedback = ""; error = "无法读取路由器。请确认网络与登录状态，再刷新；登录过期时返回首页重新登录。"; draw(); });
            }
        });
    }
    private void confirmSave() {
        if (busy || memory.snapshot == null) return;
        final Map<String, String> changed = changes();
        if (changed.isEmpty()) { feedback = "这一页没有修改。"; error = ""; stash(); draw(); return; }
        final Map<String, String> desired;
        try { desired = PluginSettings.normalize(memory.group, changed, formBase); }
        catch (IOException e) { error = e.getMessage(); feedback = ""; stash(); draw(); return; }
        StringBuilder names = new StringBuilder();
        for (Control control : controls.values()) if (changed.containsKey(control.field.key)) names.append(names.length() == 0 ? "" : "、").append(control.field.label);
        String impact = "adblock".equals(memory.group) ? "广告规则会热更新，不重启代理或 UU。" : "路由器将应用设置，代理与 DNS 可能短暂重载。UU 进程和设备自身 VPN 仍由原有配置管理。";
        new AlertDialog.Builder(this).setTitle("保存" + PluginSettings.title(memory.group) + "？")
                .setMessage("本次修改：" + names + "。\n\n" + impact)
                .setNegativeButton("继续编辑", null).setPositiveButton("保存并应用", (dialog, which) -> save(changed, desired)).show();
    }
    private void save(Map<String, String> changed, Map<String, String> desired) {
        if (busy || memory.mutationInFlight) return;
        stash(); final String group = memory.group; final Map<String, String> expected = new LinkedHashMap<>(formBase);
        final RouterApi.Snapshot baseline = memory.snapshot;
        memory.pendingGroup = group; memory.pendingDesired = new LinkedHashMap<>(desired); memory.mutationInFlight = true;
        busy = true; memory.pending = true; error = ""; feedback = "正在提交设置并读取确认，请稍候…"; draw(); final int token = ++generation;
        worker.execute(() -> {
            RouterApi.Snapshot result = null; String problem = ""; boolean submitted = false, matched = false;
            try {
                RouterApi connection = api();
                try { connection.applySettings(group, changed, expected); submitted = true; }
                catch (IOException e) { problem = e.getMessage() == null ? "无法确认提交结果。" : e.getMessage(); }
                for (int i = 0; i < 6; i++) {
                    Thread.sleep(3000);
                    try {
                        result = connection.load(); matched = matches(desired, result.config);
                        if (matched && runtimeReady(group, desired, result, baseline)) break;
                    } catch (IOException ignored) { }
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); return; }
            catch (Exception ignored) { problem = "无法确认提交结果。"; }
            finally { memory.mutationInFlight = false; }
            final RouterApi.Snapshot latest = result; final boolean confirmed = matched; final boolean accepted = submitted; final String reason = problem;
            final boolean ready = matched && runtimeReady(group, desired, result, baseline);
            ui(token, () -> {
                busy = false; memory.pending = false; memory.pendingDesired = null; memory.pendingGroup = null;
                if (confirmed) {
                    memory.drafts.remove(group); memory.bases.remove(group); memory.snapshot = latest;
                    if (!ready) feedback = "配置已保存，仍在等待路由器应用。请稍后刷新核对，避免重复提交。";
                    else if ("adblock".equals(group)) {
                        String enabled = desired.getOrDefault("ss_basic_adblock_enable", latest.config.getOrDefault("ss_basic_adblock_enable", "0"));
                        if ("1".equals(enabled) && adblockPaused(latest)) feedback = "广告配置已保存；代理关闭或处于直连保护、路径待恢复时，广告过滤暂停。";
                        else feedback = "1".equals(enabled) ? "广告配置与读取时的过滤运行状态已确认。" : "广告配置已关闭，读取时为兼容直通；旧 DNS 连接会自然释放。";
                    } else feedback = accepted ? "保存配置已读取确认；实际连通性请结合状态与设备访问核对。" : "路由器当前配置与目标一致；请核对运行状态。";
                    error = "";
                } else {
                    feedback = ""; error = (reason.isEmpty() ? "尚未确认配置已保存。" : reason) + " 请先刷新核对路由器当前配置，再决定是否重新保存。";
                }
                draw();
            });
        });
    }
    private static boolean matches(Map<String, String> expected, Map<String, String> actual) {
        for (Map.Entry<String, String> entry : expected.entrySet()) if (!entry.getValue().equals(actual.getOrDefault(entry.getKey(), ""))) return false;
        return true;
    }
    private static boolean adblockPaused(RouterApi.Snapshot loaded) {
        String mode = loaded.failover == null ? "" : loaded.failover.optString("mode");
        return !loaded.enabled || "direct".equals(mode) || "error".equals(mode);
    }
    private static boolean enabledValue(Object value, boolean enabled) {
        return Boolean.valueOf(enabled).equals(value) || (enabled ? "1" : "0").equals(String.valueOf(value))
                || (enabled ? "true" : "false").equals(String.valueOf(value));
    }
    private static boolean runtimeReady(String group, Map<String, String> desired, RouterApi.Snapshot loaded,
                                        RouterApi.Snapshot expectedBaseline) {
        if (loaded == null) return false;
        if ("adblock".equals(group)) {
            String target = desired.getOrDefault("ss_basic_adblock_enable", loaded.config.getOrDefault("ss_basic_adblock_enable", "0"));
            if ("1".equals(target) && adblockPaused(loaded)) return true;
            JSONObject state = loaded.adblock;
            if (state == null || state.optInt("version") != 1) return false;
            if ("0".equals(target)) return Boolean.FALSE.equals(state.opt("enabled"))
                    && ("off".equals(state.optString("state")) || "draining".equals(state.optString("state")))
                    && "passthrough".equals(state.optString("mode"));
            return Boolean.TRUE.equals(state.opt("enabled")) && Boolean.TRUE.equals(state.opt("running"))
                    && "active".equals(state.optString("state")) && "filter".equals(state.optString("mode"));
        }
        if ("routing".equals(group) && desired.containsKey("ss_basic_enable")) {
            JSONObject health = loaded.health;
            if (health == null) return false;
            if ("0".equals(desired.get("ss_basic_enable"))) return enabledValue(health.opt("enabled"), false)
                    && loaded.currentId.equals(health.optString("node_id"))
                    && ("disabled".equals(health.optString("status"))
                        || ("checking".equals(health.optString("status")) && health.optLong("checked_at", -1) == 0));
            long before = expectedBaseline == null || expectedBaseline.health == null ? 0 : expectedBaseline.health.optLong("checked_at");
            return enabledValue(health.opt("enabled"), true) && loaded.currentId.equals(health.optString("node_id"))
                    && health.optLong("checked_at") > before;
        }
        return true;
    }
    private void waitForMutation() {
        pendingHandler.postDelayed(() -> {
            if (!alive) return;
            if (memory.mutationInFlight) waitForMutation();
            else { busy = false; refresh(false); }
        }, 500);
    }
    private void openPanel() {
        if (busy) return;
        stash(); startActivityForResult(new Intent(this, PluginPanelActivity.class), 20);
    }
    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 20) refresh(true);
    }
    private void ui(int token, Runnable action) { runOnUiThread(() -> { if (alive && token == generation) action.run(); }); }
    private void leave() {
        if (memory.mutationInFlight) {
            new AlertDialog.Builder(this).setTitle("正在核对设置")
                    .setMessage("请求可能已经提交。请等待核对完成，避免重复操作。")
                    .setPositiveButton("继续等待", null).show(); return;
        }
        if (dirty()) new AlertDialog.Builder(this).setTitle("放弃未保存修改？")
                .setMessage("只有已点击保存的设置才会写入路由器。")
                .setNegativeButton("继续编辑", null).setPositiveButton("放弃并返回", (d, w) -> finish()).show();
        else finish();
    }
    @Override public void onBackPressed() { leave(); }
    @Override public Object onRetainNonConfigurationInstance() { stash(); memory.pending = busy || memory.pending; return memory; }
    @Override protected void onSaveInstanceState(Bundle state) {
        // Do not serialize router fields, MACs, DNS, Hosts or private drafts into the activity Bundle.
        super.onSaveInstanceState(state); state.clear();
    }
    @Override protected void onDestroy() {
        alive = false; generation++; pendingHandler.removeCallbacksAndMessages(null);
        // An HTTP POST cannot be reliably interrupted. Retain its lock until the bounded task finishes.
        if (memory.mutationInFlight) worker.shutdown(); else worker.shutdownNow();
        super.onDestroy();
    }
}
