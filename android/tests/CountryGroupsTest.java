package cn.simon.routercontrol;
public final class CountryGroupsTest {
    public static void main(String[] args) {
        check("🇭🇰 港区线路 A", "HK");
        check("Hong Kong 02", "HK");
        check("HK01", "HK");
        check("日本 · 03", "JP");
        check("JP-02", "JP");
        check("🇨🇭 Zurich", "CH");
        check("新加坡 04", "SG");
        check("台湾线路", "TW");
        check("🇹🇼 任意线路名称", "TW");
        check("Singapore Premium", "SG");
        check("United States 5", "US");
        check("俄罗斯 02", "RU");
        check("Russia 02", "RU");
        check("Brazil 03", "BR");
        check("Pause Premium", "");
        check("Unknown 01", "");
        check(null, "");
        System.out.println("CountryGroups: 17 classification checks passed");
    }
    private static void check(String value, String code) {
        String actual = CountryGroups.classify(value).code;
        if (!code.equals(actual)) throw new AssertionError("expected " + code + ", actual " + actual);
    }
}
