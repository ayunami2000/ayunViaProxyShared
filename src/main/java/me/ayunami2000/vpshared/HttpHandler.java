package me.ayunami2000.vpshared;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.viaversion.viaversion.api.protocol.version.ProtocolVersion;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import net.raphimc.minecraftauth.MinecraftAuth;
import net.raphimc.minecraftauth.step.msa.StepMsaDeviceCode;
import net.raphimc.viabedrock.api.BedrockProtocolVersion;
import net.raphimc.vialoader.util.ProtocolVersionList;
import net.raphimc.viaproxy.proxy.session.UserOptions;
import net.raphimc.viaproxy.proxy.util.ExceptionUtil;
import net.raphimc.viaproxy.saves.impl.accounts.BedrockAccount;
import net.raphimc.viaproxy.saves.impl.accounts.MicrosoftAccount;
import net.raphimc.viaproxy.saves.impl.accounts.OfflineAccount;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class HttpHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private static final File webFolder = new File("ViaLoader", "vpshared");

    static {
        webFolder.mkdirs();
    }

    private static final File captchaFile = new File(webFolder, "captcha.html");
    private static final File versionFile = new File(webFolder, "version.html");
    private static final File configFile = new File(webFolder, "config.html");
    private static final File authFile = new File(webFolder, "auth.html");
    private static final File deleteFile = new File(webFolder, "delete.html");
    private static String captchaPage;
    private static String versionPage;
    private static String configPage;
    private static String authPage;
    private static String deletePage;

    protected static void initFiles() {
        try {
            if (!captchaFile.exists()) {
                Files.copy(Objects.requireNonNull(HttpHandler.class.getResourceAsStream("/captcha.html")), captchaFile.toPath());
            }
            captchaPage = FileUtils.readFileToString(captchaFile, StandardCharsets.UTF_8).replaceAll("SITEKEYHERE", FunnyConfig.hCaptchaSiteKey);
            if (!versionFile.exists()) {
                Files.copy(Objects.requireNonNull(HttpHandler.class.getResourceAsStream("/version.html")), versionFile.toPath());
            }
            versionPage = FileUtils.readFileToString(versionFile, StandardCharsets.UTF_8);
            if (!configFile.exists()) {
                Files.copy(Objects.requireNonNull(HttpHandler.class.getResourceAsStream("/config.html")), configFile.toPath());
            }
            StringBuilder sb = new StringBuilder();
            for (ProtocolVersion v : ProtocolVersionList.getProtocolsNewToOld()) {
                sb.append(versionPage.replaceAll("VERSIONHERE", v.getName()));
            }
            configPage = FileUtils.readFileToString(configFile, StandardCharsets.UTF_8).replaceAll("VERSIONSHERE", sb.toString());
            if (!authFile.exists()) {
                Files.copy(Objects.requireNonNull(HttpHandler.class.getResourceAsStream("/auth.html")), authFile.toPath());
            }
            authPage = FileUtils.readFileToString(authFile, StandardCharsets.UTF_8);
            if (!deleteFile.exists()) {
                Files.copy(Objects.requireNonNull(HttpHandler.class.getResourceAsStream("/delete.html")), deleteFile.toPath());
            }
            deletePage = FileUtils.readFileToString(deleteFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest req) throws Exception {
        if (req.headers().contains(HttpHeaderNames.CONNECTION) && req.headers().get(HttpHeaderNames.CONNECTION).toLowerCase().contains("upgrade") && req.headers().contains(HttpHeaderNames.UPGRADE) && req.headers().get(HttpHeaderNames.UPGRADE).toLowerCase().contains("websocket")) {
            ctx.pipeline().remove(this);
            ctx.pipeline().fireChannelRead(req.retain());
            return;
        }
        if (!req.headers().contains(HttpHeaderNames.HOST)) {
            ctx.close();
            return;
        }
        String host = req.headers().get(HttpHeaderNames.HOST).toLowerCase();
        String portPart = "";
        if (host.contains(":")) {
            portPart = host.substring(host.lastIndexOf(':'));
            host = host.substring(0, host.indexOf(':'));
        }
        String base = null;
        for (String potentialBase : FunnyConfig.hostBases) {
            if (host.equals(potentialBase) || (host.contains(".") && host.split("\\.", 2)[1].equals(potentialBase))) {
                base = potentialBase;
                break;
            }
        }
        if (base == null) {
            ctx.close();
            return;
        }
        ByteBuf bb = ctx.alloc().buffer();
        if (host.equals(base)) {
            if (req.method() == HttpMethod.POST) {
                Map<String, String> params = parseQuery(new String(ByteBufUtil.getBytes(req.content()), StandardCharsets.UTF_8), 4);
                if (params.containsKey("h-captcha-response")) {
                    String key = params.get("h-captcha-response");
                    if (check(key)) {
                        String code;
                        do {
                            String uuid = UUID.randomUUID().toString().toLowerCase();
                            code = uuid.substring(uuid.lastIndexOf('-') + 1);
                        } while (Main.connMap.containsKey(code));
                        Main.connMap.put(code, new Main.ConnInfo());
                        bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + code + "." + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                    } else {
                        bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                    }
                } else {
                    bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                }
            } else {
                bb.writeCharSequence(captchaPage, StandardCharsets.UTF_8);
            }
        } else {
            String key = host.split("\\.", 2)[0];
            if (Main.connMap.containsKey(key)) {
                Main.ConnInfo connInfo = Main.connMap.get(key);
                if (req.method() == HttpMethod.POST) {
                    Map<String, String> params = parseQuery(new String(ByteBufUtil.getBytes(req.content()), StandardCharsets.UTF_8), connInfo.host == null ? 7 : 3);
                    if (connInfo.host == null && params.containsKey("username") && params.containsKey("host") && params.containsKey("port") && params.containsKey("version") && !params.get("host").isEmpty()) {
                        connInfo.host = params.get("host");
                        try {
                            connInfo.port = Integer.parseInt(params.get("port"));
                        } catch (NumberFormatException ignored) {}
                        for (ProtocolVersion v : ProtocolVersionList.getProtocolsNewToOld()) {
                            if (v.getName().equalsIgnoreCase(params.get("version"))) {
                                connInfo.version = v;
                                break;
                            }
                        }
                        if (connInfo.host.startsWith("mc://")) { // ClassiCube Direct URL
                            final URI uri = new URI(connInfo.host);
                            connInfo.host = uri.getHost();
                            connInfo.port = uri.getPort();

                            if (connInfo.port == -1) {
                                connInfo.port = 25565;
                            }

                            final String[] path = uri.getPath().substring(1).split("/");
                            if (path.length < 2) {
                                connInfo.host = null;
                                connInfo.port = 25565;
                                bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + key + "." + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                            } else {
                                connInfo.userOptions = new UserOptions(path[1], new OfflineAccount(path[0]));
                                bb.writeCharSequence(deletePage.replaceAll("AUTHHERE", connInfo.auth), StandardCharsets.UTF_8);
                            }
                        } else if (Main.hasEagUtils && (connInfo.host.toLowerCase().startsWith("ws://") || connInfo.host.toLowerCase().startsWith("wss://"))) {
                            if (params.get("username").isEmpty()) {
                                bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + key + "." + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                            } else {
                                final URI uri = new URI(connInfo.host);
                                connInfo.host = uri.getHost();
                                connInfo.port = uri.getPort();

                                final boolean secure = uri.getScheme().equalsIgnoreCase("wss");

                                if (connInfo.port == -1) {
                                    connInfo.port = secure ? 443 : 80;
                                }

                                connInfo.secureWs = secure;
                                if (!uri.getPath().isEmpty()) {
                                    connInfo.wsPath = uri.getPath().substring(1);
                                }
                                // connInfo.eagxPass = null;

                                connInfo.userOptions = new UserOptions(null, new OfflineAccount(params.get("username")));
                                bb.writeCharSequence(deletePage.replaceAll("AUTHHERE", connInfo.auth), StandardCharsets.UTF_8);
                            }
                        } else if (params.get("username").isEmpty()) {
                            Consumer<StepMsaDeviceCode.MsaDeviceCode> cb = msaDeviceCode -> {
                                connInfo.auth = authPage.replaceAll("CODEHERE", msaDeviceCode.getUserCode());
                                bb.writeCharSequence(deletePage.replaceAll("AUTHHERE", connInfo.auth), StandardCharsets.UTF_8);
                                DefaultFullHttpResponse resp = new DefaultFullHttpResponse(req.protocolVersion(), HttpResponseStatus.OK, bb);
                                resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
                                ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
                            };
                            if (connInfo.version.equals(BedrockProtocolVersion.bedrockLatest)) {
                                connInfo.userOptions = new UserOptions(null, new BedrockAccount(MinecraftAuth.BEDROCK_DEVICE_CODE_LOGIN.getFromInput(MinecraftAuth.createHttpClient(), new StepMsaDeviceCode.MsaDeviceCodeCallback(cb))));
                            } else {
                                connInfo.userOptions = new UserOptions(null, new MicrosoftAccount(MinecraftAuth.JAVA_DEVICE_CODE_LOGIN.getFromInput(MinecraftAuth.createHttpClient(), new StepMsaDeviceCode.MsaDeviceCodeCallback(cb))));
                            }
                            return;
                        } else {
                            connInfo.userOptions = new UserOptions(null, new OfflineAccount(params.get("username")));
                            bb.writeCharSequence(deletePage.replaceAll("AUTHHERE", connInfo.auth), StandardCharsets.UTF_8);
                        }
                    } else if (connInfo.host == null) {
                        bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + key + "." + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                    } else if (params.containsKey("host")) {
                        bb.writeCharSequence(deletePage.replaceAll("AUTHHERE", connInfo.auth), StandardCharsets.UTF_8);
                    } else {
                        Main.connMap.remove(key);
                        bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + base + portPart + "'\"/>", StandardCharsets.UTF_8);
                    }
                } else if (req.method() == HttpMethod.GET) {
                    bb.writeCharSequence(connInfo.host == null ? configPage : deletePage.replaceAll("CODEHERE", connInfo.auth), StandardCharsets.UTF_8);
                }
            } else {
                bb.writeCharSequence("<meta http-equiv=\"refresh\" content=\"0;URL='//" + base + portPart + "'\"/>", StandardCharsets.UTF_8);
            }
        }
        DefaultFullHttpResponse resp = new DefaultFullHttpResponse(req.protocolVersion(), HttpResponseStatus.OK, bb);
        resp.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=utf-8");
        ctx.writeAndFlush(resp).addListener(ChannelFutureListener.CLOSE);
    }

    private static boolean check(String key) {
        try {
            URL url = new URL("https://hcaptcha.com/siteverify");
            String postData = "response=" + key + "&secret=" + FunnyConfig.hCaptchaSecret;

            URLConnection conn = url.openConnection();
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Content-Length", Integer.toString(postData.length()));

            try (DataOutputStream dos = new DataOutputStream(conn.getOutputStream())) {
                dos.writeBytes(postData);
            }

            String json = new BufferedReader(new InputStreamReader(conn.getInputStream())).lines().collect(Collectors.joining("\n"));
            JsonObject jsonObject = JsonParser.parseString(json).getAsJsonObject();

            return jsonObject.get("success").getAsBoolean() && FunnyConfig.hostBases.contains(jsonObject.get("hostname").getAsString());
        } catch (IOException e) {
            return false;
        }
    }

    private static Map<String, String> parseQuery(String query, int maxQuerySize) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String[] pairs = query.split("&", maxQuerySize);
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx == -1) return query_pairs;
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ExceptionUtil.handleNettyException(ctx, cause, null, true);
    }
}
