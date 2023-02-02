package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Main {
    public static void main(String[] args) throws Exception {
        //createSSLFactory(Paths.get("/home/florian/Desktop/zertifikate/le_benno-auth-azure_privkey.pem").toFile(),
        //      Paths.get("/home/florian/Desktop/zertifikate/le_benno-auth-azure_cert.pem").toFile(),
        //        "string");
        readPrivateKeyFromFile("/home/florian/Desktop/zertifikate/le_benno-auth-azure_privkey.pem", "ECC");
    }


    public static SSLServerSocketFactory createSSLFactory(File privateKeyPem, File certificatePem, String password) throws Exception {
        final SSLContext context = SSLContext.getInstance("TLS");
        final KeyStore keystore = createKeyStore(privateKeyPem, certificatePem, password);
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keystore, password.toCharArray());
        final KeyManager[] km = kmf.getKeyManagers();
        context.init(km, null, null);
        return context.getServerSocketFactory();
    }

    /**
     * Create a KeyStore from standard PEM files
     *
     * @param privateKeyPem the private key PEM file
     * @param certificatePem the certificate(s) PEM file
     * @param the password to set to protect the private key
     */
    public static KeyStore createKeyStore(File privateKeyPem, File certificatePem, final String password)
            throws Exception, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final X509Certificate[] cert = createCertificates(certificatePem);
        final KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);
        // Import private key
        final PrivateKey key = createPEcrivateKey(privateKeyPem);
        keystore.setKeyEntry(privateKeyPem.getName(), key, password.toCharArray(), cert);
        return keystore;
    }

    public static PrivateKey readPrivateKeyFromFile(String filepath, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = Main.parsePEMFile(new File(filepath));
        return Main.getPrivateKey(bytes, algorithm);
    }

    private static byte[] parsePEMFile(File pemFile) throws IOException {
        byte[] content;

        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        try (PemReader reader = new PemReader(new FileReader(pemFile))) {
            PemObject pemObject = reader.readPemObject();
            content = pemObject.getContent();
        }

        return content;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        try {
            Set<String> algs = new TreeSet<>();
            for (Provider provider : Security.getProviders()) {
                provider.getServices().stream()
                        .filter(s -> "Cipher".equals(s.getType()))
                        .map(Provider.Service::getAlgorithm)
                        .forEach(algs::add);
            }
            algs.forEach(System.out::println);
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new NoSuchAlgorithmException("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeySpecException(e.getMessage());
        }

        return privateKey;
    }

    public static String getKeyFromFile(String filename) throws IOException {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String key = new String(keyBytes);

        return key;
    }

    //Convert private key file with ec algorithm to ECPrivateKey
    public static PrivateKey createPEcrivateKey(File privateKeyPem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = getKeyFromFile(privateKeyPem.toPath().toAbsolutePath().toString());
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN EC PARAMETERS-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END EC PARAMETERS-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("BgUrgQQAIg==\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN EC PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END EC PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replaceAll("\n", "");
        privateKeyPEM = privateKeyPEM.replaceAll(" ", "");

        byte[] keyData = Base64.getDecoder().decode(privateKeyPEM);
        EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyData);

        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey privKey = kf.generatePrivate(privKeySpec);

        return privKey;
    }

    private static PrivateKey createPrivateKey(File privateKeyPem) throws Exception {
        final BufferedReader r = new BufferedReader(new FileReader(privateKeyPem));
        String s = r.readLine();
        if (s == null || !s.contains("BEGIN PRIVATE KEY")) {
            r.close();
            throw new IllegalArgumentException("No PRIVATE KEY found");
        }
        final StringBuilder b = new StringBuilder();
        s = "";
        while (s != null) {
            if (s.contains("END PRIVATE KEY")) {
                break;
            }
            b.append(s);
            s = r.readLine();
        }
        r.close();
        final String hexString = b.toString();
        final byte[] bytes = DatatypeConverter.parseBase64Binary(hexString);
        return generatePrivateKeyFromDER(bytes);
    }

    private static X509Certificate[] createCertificates(File certificatePem) throws Exception {
        final List<X509Certificate> result = new ArrayList<>();
        final BufferedReader r = new BufferedReader(new FileReader(certificatePem));
        String s = r.readLine();
        if (s == null || !s.contains("BEGIN CERTIFICATE")) {
            r.close();
            throw new IllegalArgumentException("No CERTIFICATE found");
        }
        StringBuilder b = new StringBuilder();
        while (s != null) {
            if (s.contains("END CERTIFICATE")) {
                String hexString = b.toString();
                final byte[] bytes = DatatypeConverter.parseBase64Binary(hexString);
                X509Certificate cert = generateCertificateFromDER(bytes);
                result.add(cert);
                b = new StringBuilder();
            } else {
                if (!s.startsWith("----")) {
                    b.append(s);
                }
            }
            s = r.readLine();
        }
        r.close();

        return result.toArray(new X509Certificate[result.size()]);
    }

    private static RSAPrivateKey generatePrivateKeyFromDER(byte[] keyBytes) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        final KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(spec);
    }

    private static X509Certificate generateCertificateFromDER(byte[] certBytes) throws CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    }
}