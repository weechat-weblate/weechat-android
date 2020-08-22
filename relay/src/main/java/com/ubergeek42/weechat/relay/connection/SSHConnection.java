package com.ubergeek42.weechat.relay.connection;

import net.schmizz.sshj.AndroidConfig;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.common.SSHException;
import net.schmizz.sshj.connection.channel.direct.Parameters;
import net.schmizz.sshj.transport.verification.OpenSSHKnownHosts;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyFormat;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
import net.schmizz.sshj.userauth.keyprovider.KeyProviderUtil;
import net.schmizz.sshj.userauth.password.PasswordUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Provider;
import java.security.Security;

import static com.ubergeek42.weechat.relay.connection.RelayConnection.CONNECTION_TIMEOUT;

public class SSHConnection implements IConnection {
    static {
        setupBouncyCastle();
    }

    final private static AndroidConfig config = new AndroidConfig();

    private static int counter = 0;

    final private String hostname;
    final private int port;
    final private String sshHostname;
    final private int sshPort;

    final private String sshUsername;
    final private String sshPassword;
    final private byte[] sshKey;

    final private SSHClient ssh;

    public SSHConnection(String hostname, int port, String sshHostname, int sshPort, String sshUsername,
                         String sshPassword, byte[] sshKey, byte[] sshKnownHosts) throws IOException {
        this.hostname = hostname;
        this.port = port;
        this.sshHostname = sshHostname;
        this.sshPort = sshPort;
        this.sshUsername = sshUsername;
        this.sshPassword = sshPassword;
        this.sshKey = sshKey;

        ssh = new SSHClient(config);
        ssh.addHostKeyVerifier(new OpenSSHKnownHosts(
                new InputStreamReader(new ByteArrayInputStream(sshKnownHosts))));
    }

    ServerSocket localServerSocket = null;
    Socket forwardingSocket = null;

    @Override public Streams connect() throws IOException {
        ssh.setConnectTimeout(CONNECTION_TIMEOUT);
        ssh.connect(sshHostname, sshPort);

        if (sshKey != null && sshKey.length > 0) {
            ssh.authPublickey(sshUsername, getKeyProvider(sshKey, sshPassword.toCharArray()));
        } else {
            ssh.authPassword(sshUsername, sshPassword);
        }

        Parameters forwardingParameters = new Parameters("0.0.0.0", 0, hostname, port);
        localServerSocket = new ServerSocket(0);

        new Thread(() -> {
            try {
                ssh.newLocalPortForwarder(forwardingParameters, localServerSocket).listen();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, "locf-" + counter++).start();

        forwardingSocket = new Socket("127.0.0.1", localServerSocket.getLocalPort());
        return new Streams(forwardingSocket.getInputStream(), forwardingSocket.getOutputStream());
    }

    @SuppressWarnings({"EmptyTryBlock", "unused"})
    @Override public void disconnect() throws IOException {
        try (Closeable forwardingSocket = this.forwardingSocket;
             Closeable localServerSocket = this.localServerSocket;
             Closeable ssh = this.ssh) {}
    }

    // Android registers its own BC provider. As it might be outdated and might not include
    // all needed ciphers, we substitute it with a known BC bundled in the app.
    // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
    // of that it's possible to have another BC implementation loaded in VM.
    private static void setupBouncyCastle() {
        final Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider != null) {
            if (provider.getClass().equals(BouncyCastleProvider.class))
                return;
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    // see SSHClient.loadKeys()
    static KeyProvider getKeyProvider(byte[] key, char[] password) throws IOException {
        KeyFormat keyFormat = KeyProviderUtil.detectKeyFileFormat(
                new InputStreamReader(new ByteArrayInputStream(key)), false);
        final FileKeyProvider fileKeyProvider = Factory.Named.Util.create(
                config.getFileKeyProviderFactories(), keyFormat.toString());
        if (fileKeyProvider == null)
            throw new SSHException("No provider available for " + keyFormat + " key file");
        fileKeyProvider.init(new InputStreamReader(new ByteArrayInputStream(key)),
                PasswordUtils.createOneOff(password));
        return fileKeyProvider;
    }

    // a preference can use this to verify key/password
    static void verifyKey(byte[] key, char[] password) throws IOException {
        getKeyProvider(key, password).getPublic();
    }
}
