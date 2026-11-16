package cn.simon.routercontrol;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Classifies display names only; no provider-specific node names or targets. */
public final class CountryGroups {
    public static final class Region {
        public final String code, label, flag;
        Region(String code, String label) { this.code = code; this.label = label; this.flag = flagFor(code); }
    }
    private static final Map<String, String[]> ALIASES = new LinkedHashMap<>();
    private static final Locale CHINESE = Locale.SIMPLIFIED_CHINESE;
    private static final Region UNKNOWN = new Region("", "未分类");
    static {
        ALIASES.put("HK", new String[]{"香港", "hong kong", "hongkong", "hkg", "hk"});
        ALIASES.put("MO", new String[]{"澳门", "澳門", "macao", "macau", "mo"});
        ALIASES.put("TW", new String[]{"台湾", "台灣", "taiwan", "taipei", "台北", "tw"});
        ALIASES.put("JP", new String[]{"日本", "东京", "東京", "大阪", "japan", "tokyo", "osaka", "jp"});
        ALIASES.put("SG", new String[]{"新加坡", "狮城", "singapore", "sg"});
        ALIASES.put("US", new String[]{"美国", "美國", "美西", "美东", "洛杉矶", "圣何塞", "united states", "usa", "us"});
        ALIASES.put("GB", new String[]{"英国", "英國", "伦敦", "united kingdom", "britain", "london", "uk", "gb"});
        ALIASES.put("KR", new String[]{"韩国", "韓國", "首尔", "south korea", "korea", "seoul", "kr"});
        ALIASES.put("AU", new String[]{"澳大利亚", "澳洲", "悉尼", "australia", "sydney", "au"});
        ALIASES.put("CA", new String[]{"加拿大", "canada", "ca"});
        ALIASES.put("DE", new String[]{"德国", "德國", "法兰克福", "germany", "frankfurt", "de"});
        ALIASES.put("FR", new String[]{"法国", "法國", "巴黎", "france", "paris", "fr"});
        ALIASES.put("NL", new String[]{"荷兰", "荷蘭", "netherlands", "amsterdam", "nl"});
        ALIASES.put("RU", new String[]{"俄罗斯", "俄羅斯", "russia", "ru"});
        ALIASES.put("TR", new String[]{"土耳其", "türkiye", "turkey", "tr"});
        ALIASES.put("AE", new String[]{"阿联酋", "阿聯酋", "迪拜", "dubai", "united arab emirates", "ae"});
    }
    private CountryGroups() {}
    public static Region classify(String value) {
        String name = value == null ? "" : value.trim();
        int[] points = name.codePoints().toArray();
        for (int i = 0; i + 1 < points.length; i++) {
            if (regional(points[i]) && regional(points[i + 1])) {
                String code = "" + (char) ('A' + points[i] - 0x1F1E6) + (char) ('A' + points[i + 1] - 0x1F1E6);
                if (validCode(code)) return region(code);
            }
        }
        String lower = name.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String[]> entry : ALIASES.entrySet()) {
            for (String alias : entry.getValue()) if (matches(lower, alias)) return region(entry.getKey());
        }
        // ISO country names make unlisted countries work without provider-specific configuration.
        for (String code : Locale.getISOCountries()) {
            Locale locale = new Locale("", code);
            String chinese = locale.getDisplayCountry(CHINESE);
            String english = locale.getDisplayCountry(Locale.ENGLISH).toLowerCase(Locale.ROOT);
            if ((!chinese.isEmpty() && lower.contains(chinese)) || matches(lower, english)) return region(code);
        }
        return UNKNOWN;
    }
    private static boolean matches(String name, String token) {
        if (token.isEmpty()) return false;
        if (token.charAt(0) > 127) return name.contains(token);
        return Pattern.compile("(?:^|[^a-z])" + Pattern.quote(token) + "(?=$|[^a-z])").matcher(name).find();
    }
    public static String flagFor(String code) {
        if (code == null || code.length() != 2) return "";
        return new String(Character.toChars(0x1F1E6 + code.charAt(0) - 'A'))
                + new String(Character.toChars(0x1F1E6 + code.charAt(1) - 'A'));
    }
    public static boolean hasFlag(String value) {
        if (value == null) return false;
        int[] points = value.codePoints().toArray();
        for (int i = 0; i + 1 < points.length; i++) if (regional(points[i]) && regional(points[i + 1])) return true;
        return false;
    }
    private static boolean regional(int value) { return value >= 0x1F1E6 && value <= 0x1F1FF; }
    private static boolean validCode(String code) {
        for (String candidate : Locale.getISOCountries()) if (candidate.equals(code)) return true;
        return false;
    }
    private static Region region(String code) {
        String label = new Locale("", code).getDisplayCountry(CHINESE);
        if ("HK".equals(code)) label = "香港";
        else if ("MO".equals(code)) label = "澳门";
        else if ("TW".equals(code)) label = "台湾";
        else if ("US".equals(code)) label = "美国";
        else if ("GB".equals(code)) label = "英国";
        else if ("KR".equals(code)) label = "韩国";
        else if ("AE".equals(code)) label = "阿联酋";
        return new Region(code, label);
    }
}
