package org.example;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

public class Main {
    final static String KEYSTORE_FILENAME = "/tmp/keystore.p12";

    final static String CERTIFICATE_PATH = "path-to-cert.pem";

    final static String PRIVATE_KEY_PATH = "path-to-private-key.pem";

    final static String PASSWORD = "";


    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final X509Certificate[] cert = getCertificates(Paths.get(CERTIFICATE_PATH).toFile());
        final PrivateKey privateKey = getPrivateKey(Paths.get(PRIVATE_KEY_PATH).toFile());
        final KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null, null);
        keystore.setKeyEntry("PrivateKey-Name", privateKey, PASSWORD.toCharArray(), cert);
        keystore.store(new FileOutputStream(KEYSTORE_FILENAME), PASSWORD.toCharArray());
    }

    public static PrivateKey getPrivateKey(File pemFile) throws FileNotFoundException {
        KeyPair pair = null;
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        try (SSLPemParser reader = new SSLPemParser(new FileReader(pemFile))) {
            Object pemParser = new SSLPemParser(reader).receiveObject();
            if (pemParser instanceof PEMKeyPair) {
                pair = new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) pemParser);
                return pair.getPrivate();
            } else if (pemParser instanceof PrivateKeyInfo) {
                return new JcaPEMKeyConverter().getPrivateKey(PrivateKeyInfo.getInstance(pemParser));
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        throw new RuntimeException("no valid private key found");
    }

    public static X509Certificate[] getCertificates(File certificatePem) throws Exception {
        final List<X509Certificate> result = new ArrayList<>();
        try (PEMParser pemParser = new PEMParser(new FileReader(certificatePem))) {
            var pemObject = pemParser.readObject();
            while (pemObject != null) {
                result.add(new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) pemObject));
                pemObject = pemParser.readObject();
            }
        }
        return result.toArray(new X509Certificate[result.size()]);
    }

}