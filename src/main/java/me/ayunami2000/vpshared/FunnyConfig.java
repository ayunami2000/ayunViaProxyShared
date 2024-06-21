package me.ayunami2000.vpshared;

import com.viaversion.viaversion.util.Config;

import java.io.File;
import java.net.URL;
import java.util.*;
import java.util.logging.Logger;

public class FunnyConfig extends Config {
    public static Set<String> hostBases = new HashSet<>();
    public static String hCaptchaSecret = "";
    public static String hCaptchaSiteKey = "";
    public static String selfIpv4 = "";
    public static String selfIpv6 = "";

    protected FunnyConfig(File configFile) {
        super(configFile, Logger.getLogger("FunnyConfig"));
    }

    @Override
    public URL getDefaultConfigURL() {
        return Main.class.getResource("/vpshared.yml");
    }

    @Override
    protected void handleConfig(Map<String, Object> map) {
        Object item = map.get("host-bases");
        if (item instanceof List) {
            for (Object elem : (List) item) {
                if (elem instanceof String) {
                    hostBases.add((String) elem);
                }
            }
        }
        item = map.get("h-captcha-secret");
        if (item instanceof String) {
            hCaptchaSecret = (String) item;
        }
        item = map.get("h-captcha-site-key");
        if (item instanceof String) {
            hCaptchaSiteKey = (String) item;
        }
        item = map.get("self-ipv4");
        if (item instanceof String) {
            selfIpv4 = (String) item;
        }
        item = map.get("self-ipv6");
        if (item instanceof String) {
            selfIpv6 = (String) item;
        }
    }

    @Override
    public List<String> getUnsupportedOptions() {
        return Collections.emptyList();
    }
}