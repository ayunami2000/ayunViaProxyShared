package me.ayunami2000.vpshared;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import net.raphimc.viaproxy.proxy.util.ExceptionUtil;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class HttpInitialHandler extends ByteToMessageDecoder {
    private static SslContext sslContext;

    @Override
    protected void decode(final ChannelHandlerContext ctx, final ByteBuf in, final List<Object> out) {
        if (!ctx.channel().isOpen()) {
            return;
        }
        if (!in.isReadable()) {
            return;
        }
        if (in.readableBytes() >= 3 || in.getByte(0) != 71) {
            if ((in.readableBytes() >= 3 && in.getCharSequence(0, 3, StandardCharsets.UTF_8).equals("GET")) || (in.readableBytes() >= 4 && in.getCharSequence(0, 4, StandardCharsets.UTF_8).equals("POST"))) {
                if (HttpInitialHandler.sslContext != null) {
                    ctx.pipeline().addBefore("http-initial-handler", "http-ssl-handler", HttpInitialHandler.sslContext.newHandler(ctx.alloc()));
                }
                ctx.pipeline().addBefore("http-initial-handler", "http-codec", new HttpServerCodec());
                ctx.pipeline().addBefore("http-initial-handler", "http-aggregator", new HttpObjectAggregator(65535, true));
                ctx.pipeline().addBefore("http-initial-handler", "http-handler", new HttpHandler());
                ctx.pipeline().fireChannelRead(in.readBytes(in.readableBytes()));
            } else {
                out.add(in.readBytes(in.readableBytes()));
            }
            ctx.pipeline().remove(this);
        }
    }

    static {
        final File certFolder = new File("certs");
        if (certFolder.exists()) {
            try {
                HttpInitialHandler.sslContext = SslContextBuilder.forServer(new File(certFolder, "fullchain.pem"), new File(certFolder, "privkey.pem")).build();
            } catch (Throwable e) {
                throw new RuntimeException("Failed to load SSL context", e);
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ExceptionUtil.handleNettyException(ctx, cause, null, true);
    }
}
