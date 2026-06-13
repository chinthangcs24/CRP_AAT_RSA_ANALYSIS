import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import java.math.BigInteger;

import java.io.BufferedReader;
import java.io.FileReader;

public class ExtractRSA {

    public static void main(String[] args) throws Exception {

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb",
                "root",
                "chinthan123"
        );

        System.out.println("Connected successfully");

        BufferedReader br = new BufferedReader(
                new FileReader("top-1m.csv")
        );

        String host;

        int count = 0;

        while ((host = br.readLine()) != null && count < 10000) {

            count++;

            try {

                String[] part = host.split(",");

                host = part[1].trim();

                extractKey(host, conn);

            }
            catch(Exception ex) {

                System.out.println("FAILED: " + host);
            }
        }

        br.close();
        conn.close();
    }

    public static void extractKey(String host,
                                  Connection conn) {

        try {
            int port = 443;
            SSLSocketFactory factory =
                    (SSLSocketFactory)
                            SSLSocketFactory.getDefault();

            SSLSocket socket =
                    (SSLSocket) factory.createSocket(host, port);

            socket.setSoTimeout(3000);

            socket.startHandshake();

            SSLSession session = socket.getSession();

            X509Certificate cert =
                    (X509Certificate)
                            session.getPeerCertificates()[0];

            if (!(cert.getPublicKey() instanceof RSAPublicKey)) {
                return;
            }

            RSAPublicKey key =
                    (RSAPublicKey) cert.getPublicKey();

            BigInteger n = key.getModulus();

            BigInteger e = key.getPublicExponent();

            int keySize = n.bitLength();

            String sigAlg = cert.getSigAlgName();

            String issuer =
                    cert.getIssuerX500Principal().toString();

            String subject =
                    cert.getSubjectX500Principal().toString();

            java.util.Date notBefore =
                    cert.getNotBefore();

            java.util.Date notAfter =
                    cert.getNotAfter();

            insertIntoDB(
                    conn,
                    host,
                    n.toString(),
                    e.toString(),
                    keySize,
                    sigAlg,
                    issuer,
                    subject,
                    notBefore,
                    notAfter
            );

            System.out.println("DONE: " + host);
        }

        catch(Exception ex) {

            System.out.println("FAILED: " + host);
        }
    }

    public static void insertIntoDB(
            Connection conn,
            String host,
            String n,
            String e,
            int keySize,
            String sigAlg,
            String issuer,
            String subject,
            java.util.Date notBefore,
            java.util.Date notAfter
    ) throws Exception {

        String query =
                "INSERT INTO rsa_keys " +
                        "(host, modulus, exponent, key_size, " +
                        "signature_algorithm, issuer, subject_name, " +
                        "not_before, not_after) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

        PreparedStatement stmt =
                conn.prepareStatement(query);
        stmt.setString(1, host);
        stmt.setString(2, n);
        stmt.setString(3, e);
        stmt.setInt(4, keySize);
        stmt.setString(5, sigAlg);
        stmt.setString(6, issuer);
        stmt.setString(7, subject);
        stmt.setTimestamp(
                8,
                new java.sql.Timestamp(notBefore.getTime())
        );
        stmt.setTimestamp(
                9,
                new java.sql.Timestamp(notAfter.getTime())
        );
        stmt.executeUpdate();
        stmt.close();
    }
}
