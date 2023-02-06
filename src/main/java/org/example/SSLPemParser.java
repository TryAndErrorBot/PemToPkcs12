package org.example;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectParser;

import java.io.*;

public class SSLPemParser extends PEMParser {
    public SSLPemParser(Reader reader) {
        super(reader);
    }

    public Object receiveObject()
            throws IOException {

        PemObject obj = readPemObject();

        // Ignore EC Parameters
        while (obj != null && obj.getType().equalsIgnoreCase(TYPE_EC_PARAMETERS)) {
            obj = readPemObject();
        }

        if (obj != null) {
            String type = obj.getType();
            Object pemObjectParser = parsers.get(type);
            if (pemObjectParser != null) {
                return ((PemObjectParser) pemObjectParser).parseObject(obj);
            } else {
                throw new IOException("unrecognised object: " + type);
            }
        } else {
            return null;
        }
    }
}
