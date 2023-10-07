package me.ayunami2000.vpshared;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;
import net.jodah.expiringmap.ExpiringMap;
import net.lenni0451.lambdaevents.EventHandler;
import net.raphimc.netminecraft.constants.ConnectionState;
import net.raphimc.netminecraft.packet.IPacket;
import net.raphimc.netminecraft.packet.impl.handshake.C2SHandshakePacket;
import net.raphimc.netminecraft.util.ServerAddress;
import net.raphimc.vialegacy.protocols.release.protocol1_7_2_5to1_6_4.types.Types1_6_4;
import net.raphimc.vialoader.util.VersionEnum;
import net.raphimc.viaproxy.plugins.PluginManager;
import net.raphimc.viaproxy.plugins.ViaProxyPlugin;
import net.raphimc.viaproxy.plugins.events.Client2ProxyChannelInitializeEvent;
import net.raphimc.viaproxy.plugins.events.Client2ProxyHandlerCreationEvent;
import net.raphimc.viaproxy.plugins.events.ConnectEvent;
import net.raphimc.viaproxy.plugins.events.PreConnectEvent;
import net.raphimc.viaproxy.plugins.events.types.ITyped;
import net.raphimc.viaproxy.proxy.client2proxy.Client2ProxyHandler;
import net.raphimc.viaproxy.proxy.client2proxy.passthrough.PassthroughClient2ProxyHandler;
import net.raphimc.viaproxy.proxy.session.LegacyProxyConnection;
import net.raphimc.viaproxy.proxy.session.UserOptions;
import net.raphimc.viaproxy.proxy.util.ExceptionUtil;

import java.io.File;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

public class Main extends ViaProxyPlugin {
    public static final ExpiringMap<String, ConnInfo> connMap = ExpiringMap.builder().expiration(5, TimeUnit.MINUTES).build();
    public static boolean hasEagUtils = false;
    private static final AttributeKey<UserOptions> connAccKey = AttributeKey.newInstance("conn-acc-key");
    private static final AttributeKey<ConnInfo> connFullKey = AttributeKey.newInstance("conn-full-key");

    @Override
    public void onEnable() {
        (new FunnyConfig(new File("ViaLoader", "vpshared.yml"))).reloadConfig();
        hasEagUtils = PluginManager.getPlugin("ViaProxyEagUtils") != null;
        PluginManager.EVENT_MANAGER.register(this);
    }

    @EventHandler
    public void onEvent(Client2ProxyChannelInitializeEvent event) {
        if (event.isLegacyPassthrough()) return;
        if (hasEagUtils) {
            if (event.getType() == ITyped.Type.POST) {
                event.getChannel().pipeline().addLast("eag-detector-http", new EaglerConnectionHandler());
            }
        } else {
            if (event.getType() == ITyped.Type.PRE) {
                event.getChannel().pipeline().addLast("http-initial-handler", new HttpInitialHandler());
            }
        }
    }

    private static final Field proxyConnectionField;
    static {
        try {
            proxyConnectionField = PassthroughClient2ProxyHandler.class.getDeclaredField("proxyConnection");
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
        proxyConnectionField.setAccessible(true);
    }

    @EventHandler
    public void onEvent(Client2ProxyHandlerCreationEvent event) {
        if (event.isLegacyPassthrough()) {
            event.setHandler(new PassthroughClient2ProxyHandler() {
                @Override
                protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                    try {
                        if (msg.getUnsignedByte(0) == 2) {
                            msg.skipBytes(2);
                            Types1_6_4.STRING.read(msg);
                            String host = Types1_6_4.STRING.read(msg);
                            String key = host.split("\\.", 2)[0];
                            if (connMap.containsKey(key) && connMap.get(key).host != null) {
                                ConnInfo connInfo = connMap.remove(key);
                                msg.readerIndex(0);
                                msg.writerIndex(2);
                                Types1_6_4.STRING.write(msg, connInfo.userOptions.account().getName());
                                Types1_6_4.STRING.write(msg, connInfo.host);
                                msg.writeInt(connInfo.port);
                                ctx.channel().attr(connFullKey).set(connInfo);
                                ctx.channel().attr(AttributeKey.valueOf("eag-secure-ws")).set(connInfo.secureWs);
                                ctx.channel().attr(AttributeKey.valueOf("eag-ws-path")).set(connInfo.wsPath);
                            } else {
                                ctx.close();
                                return;
                            }
                        }
                    } catch (Exception ignored) {
                        msg.readerIndex(0);
                    }
                    super.channelRead0(ctx, msg);
                }
                @Override
                protected ServerAddress getServerAddress() {
                    try {
                        LegacyProxyConnection proxyConnection = (LegacyProxyConnection) proxyConnectionField.get(this);
                        if (proxyConnection.getC2P().hasAttr(connFullKey)) {
                            ConnInfo connInfo = proxyConnection.getC2P().attr(connFullKey).get();
                            ServerAddress addr = new ServerAddress(connInfo.host, connInfo.port);
                            if (isLocal(addr.toSocketAddress().getAddress())) {
                                return null;
                            } else {
                                return addr;
                            }
                        } else {
                            return null;
                        }
                    } catch (IllegalAccessException e) {
                        e.printStackTrace();
                        return null;
                    }
                }
            });
        } else {
            event.setHandler(new Client2ProxyHandler() {
                @Override
                protected void channelRead0(ChannelHandlerContext ctx, IPacket packet) throws Exception {
                    if (!ctx.channel().isOpen()) return;
                    if (packet instanceof C2SHandshakePacket) {
                        C2SHandshakePacket handshakePacket = (C2SHandshakePacket) packet;
                        if (handshakePacket.intendedState == ConnectionState.STATUS) {
                            ctx.close();
                        } else {
                            String key = handshakePacket.address.split("\\.", 2)[0];
                            if (connMap.containsKey(key) && connMap.get(key).host != null) {
                                ConnInfo connInfo = connMap.remove(key);
                                handshakePacket.address = connInfo.host + "\u0007" + connInfo.port + "\u0007" + connInfo.version.getName();
                                ctx.channel().attr(connAccKey).set(connInfo.userOptions);
                                ctx.channel().attr(AttributeKey.valueOf("eag-secure-ws")).set(connInfo.secureWs);
                                ctx.channel().attr(AttributeKey.valueOf("eag-ws-path")).set(connInfo.wsPath);
                                super.channelRead0(ctx, handshakePacket);
                            } else {
                                ctx.close();
                            }
                        }
                    } else {
                        super.channelRead0(ctx, packet);
                    }
                }
            });
        }
    }

    @EventHandler
    public void onEvent(ConnectEvent event) {
        if (event.getProxyConnection().getC2P().hasAttr(connAccKey)) {
            event.getProxyConnection().setUserOptions(event.getProxyConnection().getC2P().attr(connAccKey).get());
        } else {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onEvent(PreConnectEvent event) {
        if (isLocal(event.getServerAddress().toSocketAddress().getAddress())) {
            event.setCancelled(true);
        }
    }

    // thank you Lenni0451 <3
    // https://github.com/Lenni0451/NoLocalConnections/blob/ac2496b6f730e51c0acf1b9c36939bd666229110/src/main/java/net/lenni0451/nolocalconnections/Main.java#L23
    private static boolean isLocal(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()) {
            return true;
        }
        if (address.getHostAddress().equalsIgnoreCase(FunnyConfig.selfIpv4) || address.getHostAddress().equalsIgnoreCase(FunnyConfig.selfIpv6)) {
            return true;
        }
        byte[] addressBytes = address.getAddress();
        if (addressBytes.length == 4) { // Check for IPv4 local address ranges
            if (addressBytes[0] == 10) { // 10.0.0.0/8
                return true;
            }
            if (addressBytes[0] == (byte) 172 && addressBytes[1] >= 16 && addressBytes[1] <= 31) { // 172.16.0.0/12
                return true;
            }
            if (addressBytes[0] == (byte) 192 && addressBytes[1] == (byte) 168) { // 192.168.0.0/16
                return true;
            }
        }
        if (addressBytes.length == 16) { // Check for IPv6 local address ranges
            return (addressBytes[0] == (byte) 0xfe && (addressBytes[1] & (byte) 0xc0) == (byte) 0x80); // fe80::/10
        }
        return false;
    }

    static class EaglerConnectionHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
            super.userEventTriggered(ctx, evt);
            if (evt.getClass().getSimpleName().equals("EaglercraftClientConnected")) {
                ctx.pipeline().remove("eag-detector-http");
                ctx.pipeline().addAfter("ws-http-aggregator", "http-handler", new HttpHandler());
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ExceptionUtil.handleNettyException(ctx, cause, null);
        }
    }

    public static class ConnInfo {
        public UserOptions userOptions = null;
        public String host = null;
        public int port = 25565;
        public VersionEnum version = VersionEnum.r1_8;
        public String auth = "";
        public Boolean secureWs = null;
        public String wsPath = null;
    }
}