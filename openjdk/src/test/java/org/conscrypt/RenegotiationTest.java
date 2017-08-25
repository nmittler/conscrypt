/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package org.conscrypt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import libcore.java.security.TestKeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * This tests that server-initiated cipher renegotiation works properly with a Conscrypt client.
 * BoringSSL does not support user-initiated renegotiation, so we use the JDK implementation for
 * the server.
 */
@RunWith(Parameterized.class)
public class RenegotiationTest {
    private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocateDirect(0);
    private static final String[] PROTOCOLS = new String[] {"TLSv1.2"};
    private static final SSLContext CONSCRYPT_CLIENT_CONTEXT = getConscryptClientContext();
    private static final SSLContext JDK_CLIENT_CONTEXT = getJdkClientContext();
    private static final SSLContext JDK_SERVER_CONTEXT = getJdkServerContext();
    private static final String[] CIPHERS = getCipherSuites();
    private static final String RENEGOTIATION_CIPHER = CIPHERS[CIPHERS.length - 1];
    private static final byte[] MESSAGE_BYTES = "Hello".getBytes(TestUtils.UTF_8);
    private static final ByteBuffer MESSAGE_BUFFER = ByteBuffer.wrap(MESSAGE_BYTES);
    private static final int MESSAGE_LENGTH = MESSAGE_BYTES.length;

    public enum SocketType {
        FILE_DESCRIPTOR {
            @Override
            Client newClient(int port) {
                return new Client(false, port);
            }
        },
        ENGINE {
            @Override
            Client newClient(int port) {
                return new Client(true, port);
            }
        };

        abstract Client newClient(int port);
    }

    @Parameters(name = "{0}")
    public static Object[] data() {
        return new Object[] {SocketType.FILE_DESCRIPTOR};
        // TODO(nmittler): replace once https://github.com/google/conscrypt/issues/310 is fixed.
        //return new Object[] {SocketType.FILE_DESCRIPTOR, SocketType.ENGINE};
    }

    @Parameter public SocketType socketType;

    private Client client;
    private Server server;

    @Before
    public void setup() throws Exception {
        server = new Server();
        Future<?> connectedFuture = server.start();

        client = socketType.newClient(server.port());
        client.start();

        // Wait for the initial connection to complete.
        connectedFuture.get(5, TimeUnit.SECONDS);
    }

    @After
    public void teardown() {
        client.stop();
        server.stop();
    }

    @Test(timeout = 10000)
    public void test() throws Exception {
        client.sendMessage();
        Thread.sleep(100);
        client.readMessage();

        // BoringSSL will not call the verify callback on renegotiation, so the client will never
        // see the new cipher. This means there's nothing specific we can test at the application
        // layer. Instead, we're just verifying that nothing bad happens during the course of the
        // test.
        // assertEquals(RENEGOTIATION_CIPHER, client.socket.getSession().getCipherSuite());
    }

    private static SSLContext getConscryptClientContext() {
        SSLContext context = TestUtils.newContext(TestUtils.getConscryptProvider());
        return TestUtils.initSslContext(context, TestKeyStore.getClient());
    }

    private static SSLContext getJdkClientContext() {
        SSLContext context = TestUtils.newContext(TestUtils.getJdkProvider());
        return TestUtils.initSslContext(context, TestKeyStore.getClient());
    }

    private static SSLContext getJdkServerContext() {
        SSLContext context = TestUtils.newContext(TestUtils.getJdkProvider());
        return TestUtils.initSslContext(context, TestKeyStore.getServer());
    }

    private static String[] getCipherSuites() {
        Set<String> supported1 = getCiphers(JDK_CLIENT_CONTEXT);
        Set<String> supported2 = getCiphers(JDK_SERVER_CONTEXT);
        Set<String> supported3 = getCiphers(CONSCRYPT_CLIENT_CONTEXT);
        supported1.retainAll(supported2);
        supported1.retainAll(supported3);
        filterCiphers(supported1);
        return supported1.toArray(new String[supported1.size()]);
    }

    private static Set<String> getCiphers(SSLContext ctx) {
        return new HashSet<String>(Arrays.asList(ctx.getDefaultSSLParameters().getCipherSuites()));
    }

    private static void filterCiphers(Set<String> ciphers) {
        // Filter all non-TLS ciphers.
        Iterator<String> iter = ciphers.iterator();
        while (iter.hasNext()) {
            String cipher = iter.next();
            if (cipher.startsWith("SSL_") || cipher.contains("_RC4_")) {
                iter.remove();
            }
        }
    }

    private static final class Client {
        private final SSLSocket socket;

        Client(boolean useEngineSocket, int port) {
            try {
                SSLSocketFactory socketFactory = CONSCRYPT_CLIENT_CONTEXT.getSocketFactory();
                Conscrypt.SocketFactories.setUseEngineSocket(socketFactory, useEngineSocket);
                socket = (SSLSocket) socketFactory.createSocket(
                        TestUtils.getLoopbackAddress(), port);
                socket.setEnabledProtocols(PROTOCOLS);
                socket.setEnabledCipherSuites(CIPHERS);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void start() {
            try {
                socket.startHandshake();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }

        void stop() {
            try {
                socket.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void readMessage() throws IOException {
            try {
                byte[] buffer = new byte[MESSAGE_LENGTH];
                int totalBytesRead = 0;
                while (totalBytesRead < buffer.length) {
                    int remaining = buffer.length - totalBytesRead;
                    int bytesRead = socket.getInputStream().read(buffer, totalBytesRead, remaining);
                    if (bytesRead == -1) {
                        break;
                    }
                    totalBytesRead += bytesRead;
                }

                // Verify the reply is correct.
                assertEquals(MESSAGE_LENGTH, totalBytesRead);
                assertArrayEquals(MESSAGE_BYTES, buffer);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        void sendMessage() throws IOException {
            try {
                socket.getOutputStream().write(MESSAGE_BYTES);
                socket.getOutputStream().flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final class Server {
        private final ServerSocketChannel serverChannel;
        private final SSLEngine engine;
        private final ByteBuffer inboundPacketBuffer;
        private final ByteBuffer inboundAppBuffer;
        private final ByteBuffer outboundPacketBuffer;
        private SocketChannel channel;
        private ExecutorService executor;
        private volatile boolean stopping;
        private volatile Future<?> echoFuture;

        Server() throws IOException {
            serverChannel = ServerSocketChannel.open();
            serverChannel.bind(new InetSocketAddress(TestUtils.getLoopbackAddress(), 0));
            engine = JDK_SERVER_CONTEXT.createSSLEngine();
            engine.setEnabledProtocols(PROTOCOLS);
            engine.setEnabledCipherSuites(CIPHERS);
            engine.setUseClientMode(false);

            inboundPacketBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
            inboundAppBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
            outboundPacketBuffer =
                    ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
        }

        Future<?> start() throws IOException {
            executor = Executors.newSingleThreadExecutor();
            return executor.submit(new AcceptTask());
        }

        void stop() {
            try {
                stopping = true;

                if (channel != null) {
                    channel.close();
                    channel = null;
                }

                if (echoFuture != null) {
                    echoFuture.get(5, TimeUnit.SECONDS);
                }

                serverChannel.close();

                if (executor != null) {
                    executor.shutdown();
                    executor.awaitTermination(5, TimeUnit.SECONDS);
                    executor = null;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            } catch (TimeoutException e) {
                throw new RuntimeException(e);
            }
        }

        int port() {
            try {
                return ((InetSocketAddress) serverChannel.getLocalAddress()).getPort();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        private final class AcceptTask implements Runnable {
            @Override
            public void run() {
                try {
                    if (stopping) {
                        return;
                    }
                    channel = serverChannel.accept();
                    channel.configureBlocking(false);

                    doHandshake();

                    if (stopping) {
                        return;
                    }
                    echoFuture = executor.submit(new EchoTask());
                } catch (Throwable e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }
        }

        private final class EchoTask implements Runnable {
            @Override
            public void run() {
                try {
                    readMessage();
                    renegotiate();
                    reply();
                } catch (Throwable e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                }
            }

            private void renegotiate() throws Exception {
                engine.setEnabledCipherSuites(new String[] {RENEGOTIATION_CIPHER});
                doHandshake();
            }

            private void reply() throws IOException {
                SSLEngineResult result = wrap(MESSAGE_BUFFER);
                if (result.getStatus() != Status.OK) {
                    throw new RuntimeException("Wrap failed. Status: " + result.getStatus());
                }
            }

            private void readMessage() throws IOException {
                int totalProduced = 0;
                while (true) {
                    SSLEngineResult result = unwrap();
                    switch (result.getStatus()) {
                        case BUFFER_UNDERFLOW:
                        case OK: {
                            totalProduced += result.bytesProduced();
                            if (totalProduced == MESSAGE_LENGTH) {
                                return;
                            }
                            break;
                        }
                        default: {
                            throw new RuntimeException(
                                    "Unwrap failed with unexpected status: " + result.getStatus());
                        }
                    }
                }
            }
        }

        private SSLEngineResult wrap(ByteBuffer src) throws IOException {
            // Check if the engine has bytes to wrap.
            SSLEngineResult result = engine.wrap(src, outboundPacketBuffer);
            runDelegatedTasks(result, engine);

            // Write any wrapped bytes to the socket.
            outboundPacketBuffer.flip();
            channel.write(outboundPacketBuffer);
            outboundPacketBuffer.clear();

            return result;
        }

        private SSLEngineResult unwrap() throws IOException {
            // Unwrap any available bytes from the socket.
            channel.read(inboundPacketBuffer);
            inboundPacketBuffer.flip();
            SSLEngineResult result = engine.unwrap(inboundPacketBuffer, inboundAppBuffer);
            runDelegatedTasks(result, engine);

            inboundPacketBuffer.compact();
            return result;
        }

        private void doHandshake() throws IOException {
            engine.beginHandshake();

            boolean serverHandshakeFinished = false;

            do {
                // Check if the engine has bytes to wrap.
                SSLEngineResult result = wrap(EMPTY_BUFFER);

                if (isHandshakeFinished(result)) {
                    serverHandshakeFinished = true;
                }

                // Unwrap any available bytes from the socket.
                result = unwrap();

                if (isHandshakeFinished(result)) {
                    serverHandshakeFinished = true;
                }
            } while (!serverHandshakeFinished);
        }

        private boolean isHandshakeFinished(SSLEngineResult result) {
            return result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED;
        }

        private void runDelegatedTasks(SSLEngineResult result, SSLEngine engine) {
            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                for (;;) {
                    Runnable task = engine.getDelegatedTask();
                    if (task == null) {
                        break;
                    }
                    task.run();
                }
            }
        }
    }
}
