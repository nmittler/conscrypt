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
 * limitations under the License.
 */

package org.conscrypt;

import static org.conscrypt.NativeConstants.SSL_OP_CIPHER_SERVER_PREFERENCE;
import static org.conscrypt.NativeConstants.SSL_RECEIVED_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_SENT_SHUTDOWN;
import static org.conscrypt.NativeConstants.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
import static org.conscrypt.NativeConstants.SSL_VERIFY_NONE;
import static org.conscrypt.NativeConstants.SSL_VERIFY_PEER;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.conscrypt.NativeCrypto.SSLHandshakeCallbacks;

/**
 * A utility wrapper that abstracts operations on the underlying native SSL instance.
 */
final class SslWrapper {
    private final SSLParametersImpl parameters;
    private final SSLHandshakeCallbacks handshakeCallbacks;
    private final AliasChooser aliasChooser;
    private final PSKCallbacks pskCallbacks;
    private X509Certificate[] localCertificates;
    private long ssl;

    static SslWrapper newInstance(SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser chooser,
            PSKCallbacks pskCallbacks) throws SSLException {
        long ctx = parameters.getSessionContext().sslCtxNativePointer;
        long ssl = NativeCrypto.SSL_new(ctx);
        return new SslWrapper(ssl, parameters, handshakeCallbacks, chooser, pskCallbacks);
    }

    private SslWrapper(long ssl, SSLParametersImpl parameters,
            SSLHandshakeCallbacks handshakeCallbacks, AliasChooser aliasChooser,
            PSKCallbacks pskCallbacks) {
        this.ssl = ssl;
        this.parameters = parameters;
        this.handshakeCallbacks = handshakeCallbacks;
        this.aliasChooser = aliasChooser;
        this.pskCallbacks = pskCallbacks;
    }

    BioWrapper newBio() {
        try {
            return new BioWrapper();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    void offerToResumeSession(long sslSessionNativePointer) throws SSLException {
        NativeCrypto.SSL_set_session(ssl, sslSessionNativePointer);
    }

    byte[] getSessionId() {
        return NativeCrypto.SSL_session_id(ssl);
    }

    long getTime() {
        return NativeCrypto.SSL_get_time(ssl);
    }

    long getTimeout() {
        return NativeCrypto.SSL_get_timeout(ssl);
    }

    void setTimeout(long millis) {
        NativeCrypto.SSL_set_timeout(ssl, millis);
    }

    String getCipherSuite() {
        return NativeCrypto.cipherSuiteToJava(NativeCrypto.SSL_get_current_cipher(ssl));
    }

    X509Certificate[] getLocalCertificates() {
        return localCertificates;
    }

    byte[] getPeerCertificateOcspData() {
        return NativeCrypto.SSL_get_ocsp_response(ssl);
    }

    byte[] getPeerTlsSctData() {
        return NativeCrypto.SSL_get_signed_cert_timestamp_list(ssl);
    }

    /**
     * @see SSLHandshakeCallbacks#clientPreSharedKeyRequested(String, byte[], byte[])
     */
    int clientPreSharedKeyRequested(String identityHint, byte[] identityBytesOut, byte[] key) {
        @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager == null) {
            return 0;
        }

        String identity = pskCallbacks.chooseClientPSKIdentity(pskKeyManager, identityHint);
        // Store identity in NULL-terminated modified UTF-8 representation into ientityBytesOut
        byte[] identityBytes;
        if (identity == null) {
            identity = "";
            identityBytes = EmptyArray.BYTE;
        } else if (identity.isEmpty()) {
            identityBytes = EmptyArray.BYTE;
        } else {
            try {
                identityBytes = identity.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported", e);
            }
        }
        if (identityBytes.length + 1 > identityBytesOut.length) {
            // Insufficient space in the output buffer
            return 0;
        }
        if (identityBytes.length > 0) {
            System.arraycopy(identityBytes, 0, identityBytesOut, 0, identityBytes.length);
        }
        identityBytesOut[identityBytes.length] = 0;

        SecretKey secretKey = pskCallbacks.getPSKKey(pskKeyManager, identityHint, identity);
        byte[] secretKeyBytes = secretKey.getEncoded();
        if (secretKeyBytes == null) {
            return 0;
        } else if (secretKeyBytes.length > key.length) {
            // Insufficient space in the output buffer
            return 0;
        }
        System.arraycopy(secretKeyBytes, 0, key, 0, secretKeyBytes.length);
        return secretKeyBytes.length;
    }

    /**
     * @see SSLHandshakeCallbacks#serverPreSharedKeyRequested(String, String, byte[])
     */
    int serverPreSharedKeyRequested(String identityHint, String identity, byte[] key) {
        @SuppressWarnings("deprecation") // PSKKeyManager is deprecated, but in our own package
        PSKKeyManager pskKeyManager = parameters.getPSKKeyManager();
        if (pskKeyManager == null) {
            return 0;
        }
        SecretKey secretKey = pskCallbacks.getPSKKey(pskKeyManager, identityHint, identity);
        byte[] secretKeyBytes = secretKey.getEncoded();
        if (secretKeyBytes == null) {
            return 0;
        } else if (secretKeyBytes.length > key.length) {
            return 0;
        }
        System.arraycopy(secretKeyBytes, 0, key, 0, secretKeyBytes.length);
        return secretKeyBytes.length;
    }

    void chooseClientCertificate(byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals)
            throws SSLException, CertificateEncodingException {
        Set<String> keyTypesSet = SSLUtils.getSupportedClientKeyTypes(keyTypeBytes);
        String[] keyTypes = keyTypesSet.toArray(new String[keyTypesSet.size()]);

        X500Principal[] issuers = decodeIssuers(asn1DerEncodedPrincipals);

        setCertificate(chooseClientAlias(issuers, keyTypes));
    }

    String getVersion() {
        return NativeCrypto.SSL_get_version(ssl);
    }

    String getRequestedServerName() {
        return NativeCrypto.SSL_get_servername(ssl);
    }

    byte[] getTlsChannelId() throws SSLException {
        return NativeCrypto.SSL_get_tls_channel_id(ssl);
    }

    void configure(String hostname, OpenSSLKey channelIdPrivateKey) throws IOException {
        if (parameters.getEnabledProtocols().length == 0 && parameters.isEnabledProtocolsFiltered) {
            throw new SSLHandshakeException("No enabled protocols; "
                + NativeCrypto.OBSOLETE_PROTOCOL_SSLV3
                + " is no longer supported and was filtered from the list");
        }

        if (isClient()) {
            configureClient(hostname, channelIdPrivateKey);
        } else {
            configureServer(hostname, channelIdPrivateKey);
        }
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void doHandshake(FileDescriptor fd, int timeoutMillis)
            throws CertificateException, SocketTimeoutException, SSLException {
        NativeCrypto.SSL_do_handshake(ssl, fd, handshakeCallbacks, timeoutMillis);
    }

    int doHandshake() throws IOException {
        return NativeCrypto.ENGINE_SSL_do_handshake(ssl, handshakeCallbacks);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    int read(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        return NativeCrypto.SSL_read(ssl, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void write(FileDescriptor fd, byte[] buf, int offset, int len, int timeoutMillis)
            throws IOException {
        NativeCrypto.SSL_write(ssl, fd, handshakeCallbacks, buf, offset, len, timeoutMillis);
    }

    void interrupt() {
        NativeCrypto.SSL_interrupt(ssl);
    }

    // TODO(nathanmittler): Remove once after we switch to the engine socket.
    void shutdown(FileDescriptor fd) throws IOException {
        NativeCrypto.SSL_shutdown(ssl, fd, handshakeCallbacks);
    }

    void shutdown() throws IOException {
        NativeCrypto.ENGINE_SSL_shutdown(ssl, handshakeCallbacks);
    }

    boolean wasShutdownReceived() {
        return (NativeCrypto.SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != 0;
    }

    boolean wasShutdownSent() {
        return (NativeCrypto.SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) != 0;
    }

    int readDirectByteBuffer(long destAddress, int destLength)
            throws IOException, CertificateException {
        return NativeCrypto.ENGINE_SSL_read_direct(
                ssl, destAddress, destLength, handshakeCallbacks);
    }

    int writeDirectByteBuffer(long sourceAddress, int sourceLength) throws IOException {
        return NativeCrypto.ENGINE_SSL_write_direct(
                ssl, sourceAddress, sourceLength, handshakeCallbacks);
    }

    int getPendingReadableBytes() {
        return NativeCrypto.SSL_pending_readable_bytes(ssl);
    }

    int getMaxSealOverhead() {
        return NativeCrypto.SSL_max_seal_overhead(ssl);
    }

    void close() {
        NativeCrypto.SSL_free(ssl);
        ssl = 0L;
    }

    boolean isClosed() {
        return ssl == 0L;
    }

    int getError(int result) {
        return NativeCrypto.SSL_get_error(ssl, result);
    }

    byte[] getAlpnSelectedProtocol() {
        return NativeCrypto.SSL_get0_alpn_selected(ssl);
    }

    /**
     * A utility wrapper that abstracts operations on the underlying native BIO instance.
     */
    final class BioWrapper {
        private long bio;

        private BioWrapper() throws SSLException {
            this.bio = NativeCrypto.SSL_BIO_new(ssl);
        }

        int getPendingWrittenBytes() {
            return NativeCrypto.SSL_pending_written_bytes_in_BIO(bio);
        }

        int writeDirectByteBuffer(long address, int length) throws IOException {
            return NativeCrypto.ENGINE_SSL_write_BIO_direct(
                    ssl, bio, address, length, handshakeCallbacks);
        }

        int readDirectByteBuffer(long destAddress, int destLength) throws IOException {
            return NativeCrypto.ENGINE_SSL_read_BIO_direct(
                    ssl, bio, destAddress, destLength, handshakeCallbacks);
        }

        void close() {
            NativeCrypto.BIO_free_all(bio);
            bio = 0L;
        }
    }

    private void configureClient(String hostname, OpenSSLKey channelIdPrivateKey) throws IOException {
        if (!parameters.getEnableSessionCreation()) {
            NativeCrypto.SSL_set_session_creation_enabled(ssl, false);
        }
        NativeCrypto.setEnabledProtocols(ssl, parameters.enabledProtocols);
        NativeCrypto.setEnabledCipherSuites(ssl, parameters.enabledCipherSuites);
        if (parameters.alpnProtocols != null) {
            NativeCrypto.SSL_configure_alpn(ssl, isClient(), parameters.alpnProtocols);
        }
        NativeCrypto.enableSessionTickets(ssl, parameters.useSessionTickets);
        if (parameters.getUseSni() && AddressUtils.isValidSniHostname(hostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(ssl, hostname);
        }

        NativeCrypto.SSL_set_connect_state(ssl);

        // Configure OCSP and CT extensions for client
        NativeCrypto.SSL_enable_ocsp_stapling(ssl);
        if (parameters.isCTVerificationEnabled(hostname)) {
            NativeCrypto.SSL_enable_signed_cert_timestamps(ssl);
        }

        if (isPreSharedKeyExchangeRequested()) {
            NativeCrypto.set_SSL_psk_client_callback_enabled(ssl, true);
        }

        if (parameters.channelIdEnabled) {
            if (channelIdPrivateKey == null) {
                throw new SSLHandshakeException("Invalid TLS channel ID key specified");
            }
            NativeCrypto.SSL_set1_tls_channel_id(ssl, channelIdPrivateKey.getNativeRef());
        }
    }

    private void configureServer(String hostname, OpenSSLKey channelIdPrivateKey)  throws IOException {
        if (!parameters.getEnableSessionCreation()) {
            NativeCrypto.SSL_set_session_creation_enabled(ssl, false);
        }
        NativeCrypto.setEnabledProtocols(ssl, parameters.enabledProtocols);
        NativeCrypto.setEnabledCipherSuites(ssl, parameters.enabledCipherSuites);
        if (parameters.alpnProtocols != null) {
            NativeCrypto.SSL_configure_alpn(ssl, isClient(), parameters.alpnProtocols);
        }
        NativeCrypto.enableSessionTickets(ssl, parameters.useSessionTickets);
        if (parameters.getUseSni() && AddressUtils.isValidSniHostname(hostname)) {
            NativeCrypto.SSL_set_tlsext_host_name(ssl, hostname);
        }

        NativeCrypto.SSL_set_accept_state(ssl);

        // Configure OCSP for server
        if (parameters.getOCSPResponse() != null) {
            NativeCrypto.SSL_enable_ocsp_stapling(ssl);
        }

        NativeCrypto.SSL_set_options(ssl, SSL_OP_CIPHER_SERVER_PREFERENCE);

        if (parameters.sctExtension != null) {
            NativeCrypto.SSL_set_signed_cert_timestamp_list(ssl, parameters.sctExtension);
        }

        if (parameters.ocspResponse != null) {
            NativeCrypto.SSL_set_ocsp_response(ssl, parameters.ocspResponse);
        }

        if (isPreSharedKeyExchangeRequested()) {
            NativeCrypto.set_SSL_psk_server_callback_enabled(ssl, true);
            String identityHint =
                pskCallbacks.chooseServerPSKIdentityHint(parameters.getPSKKeyManager());
            NativeCrypto.SSL_use_psk_identity_hint(ssl, identityHint);
        }

        configureClientAuth();

        if (parameters.channelIdEnabled) {
            // Server-side TLS Channel ID
            NativeCrypto.SSL_enable_tls_channel_id(ssl);
        }

        // setup server certificates and private keys.
        // clients will receive a call back to request certificates.
        String[] authMethods = NativeCrypto.getAuthenticationMethods(ssl);
        Set<String> aliases = new HashSet<String>(authMethods.length);
        for (String authMethod : authMethods) {
            String type = SSLUtils.getServerX509KeyType(authMethod);
            if (type != null) {
                String alias = chooseServerAlias(type);
                if (alias != null && aliases.add(alias)) {
                    try {
                        if (setCertificate(alias)) {
                            // BoringSSL only supports a single cert chain. If we successfully
                            // set a cert chain, we're done.
                            break;
                        }
                    } catch (CertificateEncodingException e) {
                        throw new IOException(e);
                    }
                }
            }
        }
    }

    private boolean isClient() {
        return parameters.getUseClientMode();
    }

    private X509KeyManager keyManager() {
        return parameters.getX509KeyManager();
    }

    private String chooseClientAlias(X500Principal[] issuers, String[] keyTypes) {
        X509KeyManager keyManager = keyManager();
        return (keyManager != null)
            ? aliasChooser.chooseClientAlias(keyManager, issuers, keyTypes)
            : null;
    }

    private String chooseServerAlias(String type) {
        return aliasChooser.chooseServerAlias(keyManager(), type);
    }

    private static X500Principal[] decodeIssuers(byte[][] asn1DerEncodedPrincipals) {
        if (asn1DerEncodedPrincipals == null) {
            return null;
        }
        X500Principal[] issuers = new X500Principal[asn1DerEncodedPrincipals.length];
        for (int i = 0; i < asn1DerEncodedPrincipals.length; i++) {
            issuers[i] = new X500Principal(asn1DerEncodedPrincipals[i]);
        }
        return issuers;
    }

    /**
     * Determines if Pre-Shared Key (PSK) key exchange is requested.
     */
    private boolean isPreSharedKeyExchangeRequested() {
        if (parameters.getPSKKeyManager() == null) {
            return false;
        }

        for (String enabledCipherSuite : parameters.enabledCipherSuites) {
            if ((enabledCipherSuite != null) && (enabledCipherSuite.contains("PSK"))) {
                return true;
            }
        }

        return false;
    }

    private boolean setCertificate(String alias) throws CertificateEncodingException, SSLException {
        if (alias == null) {
            return false;
        }
        X509KeyManager keyManager = keyManager();
        if (keyManager == null) {
            return false;
        }
        PrivateKey privateKey = keyManager.getPrivateKey(alias);
        if (privateKey == null) {
            return false;
        }
        X509Certificate[] certChain = keyManager.getCertificateChain(alias);
        if (certChain == null) {
            return false;
        }
        int numLocalCerts = certChain.length;
        PublicKey publicKey = (numLocalCerts > 0) ? certChain[0].getPublicKey() : null;

        // Encode the local certificates.
        byte[][] encodedLocalCerts = new byte[numLocalCerts][];
        for (int i = 0; i < numLocalCerts; ++i) {
            encodedLocalCerts[i] = certChain[i].getEncoded();
        }

        // Convert the key so we can access a native reference.
        final OpenSSLKey key;
        try {
            key = OpenSSLKey.fromPrivateKeyForTLSStackOnly(privateKey, publicKey);
        } catch (InvalidKeyException e) {
            throw new SSLException(e);
        }

        // Set the local certs and private key.
        NativeCrypto.setLocalCertsAndPrivateKey(ssl, encodedLocalCerts, key.getNativeRef());

        // BoringSSL only stores a single cert chain (i.e. overwrites it on each call to
        // SSL_set_chain_and_key). We can safely store off the single instance of the certChain now,
        // since it will match BoringSSL.
        localCertificates = certChain;
        return true;
    }

    private void configureClientAuth() throws SSLException {
        // needing client auth takes priority...
        if (parameters.getNeedClientAuth()) {
            configureClientAuth(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        } else if (parameters.getWantClientAuth()) {
            configureClientAuth(SSL_VERIFY_PEER);
        } else {
            configureClientAuth(SSL_VERIFY_NONE);
        }
    }

    private void configureClientAuth(int mode) throws SSLException {
        NativeCrypto.SSL_set_verify(ssl, mode);

        X509TrustManager trustManager = parameters.getX509TrustManager();
        X509Certificate[] issuers = trustManager.getAcceptedIssuers();
        if (issuers != null && issuers.length != 0) {
            byte[][] issuersBytes;
            try {
                issuersBytes = SSLUtils.encodeIssuerX509Principals(issuers);
            } catch (CertificateEncodingException e) {
                throw new SSLException("Problem encoding principals", e);
            }
            NativeCrypto.SSL_set_client_CA_list(ssl, issuersBytes);
        }
    }
}
