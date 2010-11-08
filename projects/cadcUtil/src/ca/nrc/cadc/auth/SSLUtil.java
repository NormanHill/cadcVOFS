/*
 ************************************************************************
 *******************  CANADIAN ASTRONOMY DATA CENTRE  *******************
 **************  CENTRE CANADIEN DE DONNÉES ASTRONOMIQUES  **************
 *
 *  (c) 2009.                            (c) 2009.
 *  Government of Canada                 Gouvernement du Canada
 *  National Research Council            Conseil national de recherches
 *  Ottawa, Canada, K1A 0R6              Ottawa, Canada, K1A 0R6
 *  All rights reserved                  Tous droits réservés
 *
 *  NRC disclaims any warranties,        Le CNRC dénie toute garantie
 *  expressed, implied, or               énoncée, implicite ou légale,
 *  statutory, of any kind with          de quelque nature que ce
 *  respect to the software,             soit, concernant le logiciel,
 *  including without limitation         y compris sans restriction
 *  any warranty of merchantability      toute garantie de valeur
 *  or fitness for a particular          marchande ou de pertinence
 *  purpose. NRC shall not be            pour un usage particulier.
 *  liable in any event for any          Le CNRC ne pourra en aucun cas
 *  damages, whether direct or           être tenu responsable de tout
 *  indirect, special or general,        dommage, direct ou indirect,
 *  consequential or incidental,         particulier ou général,
 *  arising from the use of the          accessoire ou fortuit, résultant
 *  software.  Neither the name          de l'utilisation du logiciel. Ni
 *  of the National Research             le nom du Conseil National de
 *  Council of Canada nor the            Recherches du Canada ni les noms
 *  names of its contributors may        de ses  participants ne peuvent
 *  be used to endorse or promote        être utilisés pour approuver ou
 *  products derived from this           promouvoir les produits dérivés
 *  software without specific prior      de ce logiciel sans autorisation
 *  written permission.                  préalable et particulière
 *                                       par écrit.
 *
 *  This file is part of the             Ce fichier fait partie du projet
 *  OpenCADC project.                    OpenCADC.
 *
 *  OpenCADC is free software:           OpenCADC est un logiciel libre ;
 *  you can redistribute it and/or       vous pouvez le redistribuer ou le
 *  modify it under the terms of         modifier suivant les termes de
 *  the GNU Affero General Public        la “GNU Affero General Public
 *  License as published by the          License” telle que publiée
 *  Free Software Foundation,            par la Free Software Foundation
 *  either version 3 of the              : soit la version 3 de cette
 *  License, or (at your option)         licence, soit (à votre gré)
 *  any later version.                   toute version ultérieure.
 *
 *  OpenCADC is distributed in the       OpenCADC est distribué
 *  hope that it will be useful,         dans l’espoir qu’il vous
 *  but WITHOUT ANY WARRANTY;            sera utile, mais SANS AUCUNE
 *  without even the implied             GARANTIE : sans même la garantie
 *  warranty of MERCHANTABILITY          implicite de COMMERCIALISABILITÉ
 *  or FITNESS FOR A PARTICULAR          ni d’ADÉQUATION À UN OBJECTIF
 *  PURPOSE.  See the GNU Affero         PARTICULIER. Consultez la Licence
 *  General Public License for           Générale Publique GNU Affero
 *  more details.                        pour plus de détails.
 *
 *  You should have received             Vous devriez avoir reçu une
 *  a copy of the GNU Affero             copie de la Licence Générale
 *  General Public License along         Publique GNU Affero avec
 *  with OpenCADC.  If not, see          OpenCADC ; si ce n’est
 *  <http://www.gnu.org/licenses/>.      pas le cas, consultez :
 *                                       <http://www.gnu.org/licenses/>.
 *
 *  $Revision: 4 $
 *
 ************************************************************************
 */

package ca.nrc.cadc.auth;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import org.apache.log4j.Logger;

import ca.nrc.cadc.util.Base64;
import ca.nrc.cadc.util.FileUtil;

/**
 * Utility class to setup SSL before trying to use HTTPS.
 * 
 * @author pdowler
 */
public class SSLUtil
{
    private static Logger log = Logger.getLogger(SSLUtil.class);

    // SSL, SSLv2mm SSLv3, TLS, TLSv1, TLSv1.1
    private static final String SSL_PROTOCOL = "TLS";

    // jceks, jks, pkcs12
    private static final String KEYSTORE_TYPE = "JKS";

    // SunX509
    private static final String KEYMANAGER_ALGORITHM = "SunX509";

    private static final String CERT_ALIAS = "opencadc_x509";

    private static final char[] THE_PASSWORD = CERT_ALIAS.toCharArray();

    /**
     * Initialise the default SSL socket factory so that all HTTPS
     * connections use the provided key store to authenticate (when the
     * server requies client authentication).
     * 
     * @see HttpsURLConnection#setDefaultSSLSocketFactory(javax.net.ssl.SSLSocketFactory)
     * @param certFile
     *            proxy certificate
     * @param keyFile
     *            private key file in DER format
     */
    public static void initSSL(File certFile, File keyFile)
    {
        SSLSocketFactory sf = getSocketFactory(certFile, keyFile);
        HttpsURLConnection.setDefaultSSLSocketFactory(sf);
    }

    /**
     * Initialise the default SSL socket factory so that all HTTPS
     * connections use the provided key store to authenticate (when the
     * server requies client authentication).
     * 
     * @param certFile
     *            proxy certificate
     * @param keyFile
     *            private key file in DER format
     * @return configured SSL socket factory
     */
    public static SSLSocketFactory getSocketFactory(File certFile,
            File keyFile)
    {
        KeyStore ks = getKeyStore(certFile, keyFile);
        KeyStore ts = null;
        return getSocketFactory(ks, ts);
    }

    /**
     * Create an SSLSocketfactory from the credentials in the specified
     * Subject. This method extracts a X509CertificateChain from the
     * public credentials and uses the certificate chain and private key
     * found there to set up a KeyStore for the SSLSocketFactory.
     * 
     * @param s
     * @return an SSLSocketFactory, or null if no X509CertificateChain can
     *         be found
     */
    public static SSLSocketFactory getSocketFactory(Subject s)
    {
        X509CertificateChain chain = null;
        if (s != null)
        {
            Set<X509CertificateChain> certs = s
                    .getPublicCredentials(X509CertificateChain.class);
            if (certs.size() > 0)
                chain = certs.iterator().next();
        }
        if (chain == null)
            return null;
        return getSocketFactory(chain);
    }

    public static SSLSocketFactory getSocketFactory(
            X509CertificateChain chain)
    {
        KeyStore ks = null;
        if (chain != null)
            ks = getKeyStore(chain.getChain(), chain.getPrivateKey());
        KeyStore ts = null;
        return getSocketFactory(ks, ts);
    }

    public static Subject createSubject(File certFile, File keyFile)
    {
        try
        {
            PrivateKey pk = readPrivateKey(keyFile);
            X509Certificate[] chain = readCertificateChain(certFile);
            return AuthenticationUtil.getSubject(chain, pk);
        }
        catch (InvalidKeySpecException ex)
        {
            throw new RuntimeException(
                    "failed to read RSA private key from " + keyFile, ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException(
                    "BUG: failed to create empty KeyStore", ex);
        }
        catch (FileNotFoundException ex)
        {
            throw new RuntimeException(
                    "failed to find certificate and/or key file "
                            + certFile + "," + keyFile, ex);
        }
        catch (IOException ex)
        {
            throw new RuntimeException("failed to read certificate file "
                    + certFile, ex);
        }
        catch (CertificateException ex)
        {
            throw new RuntimeException(
                    "failed to load certificate from file " + certFile,
                    ex);
        }
    }

    // may in future try to support other KeyStore formats
    static SSLSocketFactory getSocketFactory(KeyStore keyStore,
            KeyStore trustStore)
    {
        KeyManagerFactory kmf = getKeyManagerFactory(keyStore);
        TrustManagerFactory tmf = getTrustManagerFactory(trustStore);
        SSLContext ctx = getContext(kmf, tmf, keyStore);
        SSLSocketFactory sf = ctx.getSocketFactory();
        return sf;
    }

    // not working due to Base64 decoding to byte array not producing
    // valid DER format key

    static byte[] getPrivateKey(byte[] certBuf) throws IOException
    {
        BufferedReader rdr = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(certBuf)));
        String line = rdr.readLine();
        StringBuffer base64 = new StringBuffer();
        while (line != null)
        {
            if (line.startsWith("-----BEGIN RSA PRIVATE KEY-"))
            {
                log.debug(line);
                line = rdr.readLine();
                while (line != null
                        && !line.startsWith("-----END RSA PRIVATE KEY-"))
                {
                    log.debug(line + " (" + line.length() + ")");
                    base64.append(line.trim());
                    line = rdr.readLine();
                }
                log.debug(line);
                line = null; // break from outer loop
            }
            else
                line = rdr.readLine();
        }
        rdr.close();
        String encoded = base64.toString();
        log.debug("RSA PRIVATE KEY: " + encoded);
        log.debug("RSA private key: " + encoded.length() + " chars");
        // now: base64 -> byte[]
        byte[] ret = Base64.decode(encoded);
        log.debug("RSA private key: " + ret.length + " bytes");

        return ret;
    }
    
    /**
     * Extracts all the certificates from the argument, decodes them
     * from base64 to byte[] and concatenates all the certificates 
     * preserving the order.
     * @param certBuf bufer containing certificates
     * @return decoded certificate chain
     * @throws IOException
     */
    static byte[] getCertificates(byte[] certBuf) throws IOException
    {
        BufferedReader rdr = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(certBuf)));
        String line = rdr.readLine();
        
        List<byte[]> certs = new ArrayList<byte[]>(); //list of byte certificates
        int byteSize = 0;
        while (line != null)
        {
            StringBuffer base64 = new StringBuffer();
            if (line.startsWith("-----BEGIN CERTIFICATE-"))
            {
                log.debug(line);
                line = rdr.readLine();
                while (line != null
                        && !line.startsWith("-----END CERTIFICATE-"))
                {
                    log.debug(line + " (" + line.length() + ")");
                    base64.append(line.trim());
                    line = rdr.readLine();
                }
                if (line.startsWith("-----END CERTIFICATE-"))
                {
                    String encoded = base64.toString();
                    log.debug("CERTIFICATE: " + encoded);
                    byte[] tmp = Base64.decode(encoded);
                    byteSize += tmp.length;
                    certs.add(tmp);
                }
                log.debug(line);
            }
            else
                line = rdr.readLine();
        }
        rdr.close();
        
        // flatten out the certificate bytes into one byte[]
        byte[] result = new byte[byteSize];
        byteSize = 0;
        for( byte[] cert : certs)
        {
            System.arraycopy(cert, 0, result, byteSize, cert.length);
            byteSize += cert.length;
            log.debug("CERTIFICATE: " + result);
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static X509Certificate[] readCertificateChain(File certFile)
            throws CertificateException, IOException
    {
        byte[] certBuf = FileUtil.readFile(certFile);
        BufferedInputStream istream = new BufferedInputStream(
                new ByteArrayInputStream(certBuf));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ArrayList certs = new ArrayList();
        while (istream.available() > 0)
        {
            Certificate cert = cf.generateCertificate(istream);
            log.debug("found: " + cert);
            certs.add(cert);
        }
        istream.close();

        X509Certificate[] chain = new X509Certificate[certs.size()];
        Iterator i = certs.iterator();
        int c = 0;
        while (i.hasNext())
        {
            X509Certificate x509 = (X509Certificate) i.next();
            chain[c++] = x509;
            try
            {
                x509.checkValidity();
            }
            catch (CertificateException ex)
            {
                throw new RuntimeException("certificate from file "
                        + certFile + " is not valid", ex);
            }
            log.debug("X509 certificate is valid");
        }
        return chain;
    }

    public static PrivateKey readPrivateKey(File keyFile) 
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException
    {
        byte[] priv = FileUtil.readFile(keyFile);
        return readPrivateKey(priv);
    }
    
    public static PrivateKey readPrivateKey(byte[] bytesPrivateKey) 
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException
    {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesPrivateKey);
        PrivateKey pk = kf.generatePrivate(spec);
        return pk;
    }

    static KeyStore getKeyStore(Certificate[] chain, PrivateKey pk)
    {
        try
        {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            try
            {
                ks.load(null, null);
            } // empty
            catch (Exception ignore)
            {
            }
            @SuppressWarnings("unused")
            KeyStore.Entry ke = new KeyStore.PrivateKeyEntry(pk, chain);
            ks.setKeyEntry(CERT_ALIAS, pk, THE_PASSWORD, chain);
            return ks;
        }
        catch (KeyStoreException ex)
        {
            throw new RuntimeException(
                    "failed to find/load KeyStore of type "
                            + KEYSTORE_TYPE, ex);
        }
    }

    static KeyStore getKeyStore(File certFile, File keyFile)
    {
        try
        {
            PrivateKey pk = readPrivateKey(keyFile);
            Certificate[] chain = readCertificateChain(certFile);
            return getKeyStore(chain, pk);
        }
        catch (InvalidKeySpecException ex)
        {
            throw new RuntimeException(
                    "failed to read RSA private key from " + keyFile, ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException(
                    "BUG: failed to create empty KeyStore", ex);
        }
        catch (FileNotFoundException ex)
        {
            throw new RuntimeException(
                    "failed to find certificate and/or key file "
                            + certFile + "," + keyFile, ex);
        }
        catch (IOException ex)
        {
            throw new RuntimeException("failed to read certificate file "
                    + certFile, ex);
        }
        catch (CertificateException ex)
        {
            throw new RuntimeException(
                    "failed to load certificate from file " + certFile,
                    ex);
        }
    }

    // currently broken trying to parse the openssl-generated pkcs12 file
    static KeyStore readPKCS12(File f)
    {
        InputStream istream = null;
        try
        {
            istream = new FileInputStream(f);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(istream, THE_PASSWORD); // assume a
                                            // non-password-protected
                                            // proxy cert
            return ks;
        }
        catch (KeyStoreException ex)
        {
            throw new RuntimeException("failed to find KeyStore for "
                    + KEYSTORE_TYPE, ex);
        }
        catch (FileNotFoundException ex)
        {
            throw new RuntimeException("failed to find key store file "
                    + f, ex);
        }
        catch (IOException ex)
        {
            throw new RuntimeException("failed to read key store file "
                    + f, ex);
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException(
                    "failed to check integtrity of key store file " + f,
                    ex);
        }
        catch (CertificateException ex)
        {
            throw new RuntimeException(
                    "failed to load proxy certificate(s) from key store file "
                            + f, ex);
        }
        finally
        {
            try
            {
                istream.close();
            }
            catch (Throwable ignore)
            {
            }
        }
    }

    static KeyManagerFactory getKeyManagerFactory(KeyStore keyStore)
    {
        String da = KEYMANAGER_ALGORITHM;
        try
        {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(da);
            kmf.init(keyStore, THE_PASSWORD); // assume a
                                                // non-password-protected
                                                // proxy cert
            return kmf;
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException(
                    "failed to find KeyManagerFactory for " + da, ex);
        }
        catch (KeyStoreException ex)
        {
            throw new RuntimeException(
                    "failed to init KeyManagerFactory", ex);
        }
        catch (UnrecoverableKeyException ex)
        {
            throw new RuntimeException(
                    "failed to init KeyManagerFactory", ex);
        }
    }

    static TrustManagerFactory getTrustManagerFactory(KeyStore trustStore)
    {
        try
        {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    "PKIX", "SunJSSE");
            tmf.init(trustStore);
            return tmf;
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException(
                    "BUG: failed to create TrustManagerFactory for algorithm=PKIX",
                    ex);
        }
        catch (NoSuchProviderException ex)
        {
            throw new RuntimeException(
                    "BUG: failed to create TrustManagerFactory for provider=SunJSSE",
                    ex);
        }
        catch (KeyStoreException ex)
        {
            throw new RuntimeException(
                    "failed to init trustManagerFactory", ex);
        }
    }

    static SSLContext getContext(KeyManagerFactory kmf,
            TrustManagerFactory tmf, KeyStore ks)
    {
        try
        {
            KeyManager[] kms = kmf.getKeyManagers();
            for (int i = 0; i < kms.length; i++)
            {
                // cast is safe since we used KEYMANAGER_ALGORITHM=SunX509
                // above
                BasicX509KeyManager wrapper = new BasicX509KeyManager(
                        (X509KeyManager) kms[i], CERT_ALIAS);
                kms[i] = wrapper;
            }
            TrustManager[] tms = tmf.getTrustManagers();
            for (int i = 0; i < tms.length; i++)
            {
                // safe cast since we used PKIX, SunJSSE above
                BasicX509TrustManager wrapper = new BasicX509TrustManager(
                        (X509TrustManager) tms[i]);
                tms[i] = wrapper;
            }
            SSLContext ctx = SSLContext.getInstance(SSL_PROTOCOL);
            log.debug("KMF returned " + kms.length + " KeyManagers");
            log.debug("TMF returned " + tms.length + " TrustManagers");
            ctx.init(kms, tms, null);
            return ctx;
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new RuntimeException("failed to find SSLContext for "
                    + SSL_PROTOCOL, ex);
        }
        catch (KeyManagementException ex)
        {
            throw new RuntimeException("failed to init SSLContext", ex);
        }
    }

    @SuppressWarnings("unchecked")
    static void printKeyStoreInfo(KeyStore keystore)
            throws KeyStoreException
    {
        log.debug("Provider : " + keystore.getProvider().getName());
        log.debug("Type : " + keystore.getType());
        log.debug("Size : " + keystore.size());

        Enumeration en = keystore.aliases();
        while (en.hasMoreElements())
        {
            System.out.println("Alias: " + en.nextElement());
        }
    }
    
    /**
     * Convenience method to parse a PEM encoded file and return the
     * corresponding X509 Certificate chain.
     * 
     * @param pemFile
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     */
    public static X509CertificateChain readPemCertificateAndKey(File pemFile) 
    throws InvalidKeySpecException, NoSuchAlgorithmException,
    IOException, CertificateException
    {
        byte[] data = FileUtil.readFile(pemFile);
        return readPemCertificateAndKey(data);
    }
    
    /**
     * Parses PEM encoded data that contains certificates and a key and 
     * returns the corresponponding X509CertificateChain that can be used to
     * create an SSL socket. RSA is the only supporting encoding for the key.
     * 
     * @param data content encoded as PEM. 
     * @return X509 Certificate chain.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     */
    public static X509CertificateChain readPemCertificateAndKey(byte[] data) 
    throws InvalidKeySpecException, NoSuchAlgorithmException,
    IOException, CertificateException
    {
        // Currently only RSA keys are supported. If the need to support
        // other encoding algorithms arises in the future, then the
        // PEMReader in the bouncycastle package should be a good
        // candidate for the job. To use this class without creating a
        // dependency on the bc package, the implementation of this method
        // can be change to look for the bc PEMReader in the classpath and
        // use it if present, otherwise default to the RSA implementation
        // below. Clients that want to use other encoding schemas will
        // have to pass the PEMReader class into the class path themselves.
        
        
        byte[] key = getPrivateKey(data);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKeySpec spec = parseKeySpec(key);
        PrivateKey pk = kf.generatePrivate(spec);
        log.debug("Private Key" + pk.toString());
        
        
        byte[] certificates = getCertificates(data);
        BufferedInputStream istream = new BufferedInputStream(
                new ByteArrayInputStream(certificates));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ArrayList<Certificate> certs = new ArrayList<Certificate>();
        while (istream.available() > 0)
        {
            Certificate cert = cf.generateCertificate(istream);
            log.debug("found: " + cert);
            certs.add(cert);
        }
        istream.close();

        X509Certificate[] chain = new X509Certificate[certs.size()];
        Iterator<Certificate> i = certs.iterator();
        int c = 0;
        while (i.hasNext())
        {
            X509Certificate x509 = (X509Certificate) i.next();
            chain[c++] = x509;
            try
            {
                x509.checkValidity();
            }
            catch (CertificateException ex)
            {
                throw new RuntimeException("certificate from file is not valid", ex);
            }
            log.debug("X509 certificate is valid");
        }
        
        return new X509CertificateChain(chain, pk);
        
    }
        

    
    /**
     * Parses a byte array and constructs the corresponding RSAPrivateCrtKeySpec.
     * Adapted from the standard. Very cryptic, but it works - so do not touch!
     * 
     * @param code byte array containing the key
     * @return RSAPrivateCrtKeySpec
     * @throws IOException
     */
    private static RSAPrivateCrtKeySpec parseKeySpec(byte[] code) throws IOException
    {
        int pos;
        BigInteger[] ints = new BigInteger[8];;
        pos = 0;
        if (code[pos] == 0x30) {
            pos = 1;
            int nb = 0;
            if ((code[pos] & 0x80) == 0x80) {
                int n = (int) code[pos] & 0x7f;
                pos = pos + 1;
                for (int i = 0; i < n; ++i) {
                    nb = (nb << 8) | (code[pos] & 0xff);
                    pos = pos + 1;
                }
            } else {
                nb = (int) code[pos];
                pos = pos + 1;
            }
            
            // skip the first version
            if (code[pos] != 2)
                throw new IllegalArgumentException("encountered invalid integer tag "
                    + ((int) code[pos]) + " at " + pos);
            pos = pos + 1;
            int len = 0;
            if ((code[pos] & 0x80) == 0x80) {
                int n = (int) code[pos] & 0x7f;
                pos = pos + 1;
                for (int i = 0; i < n; ++i) {
                    len = (len << 8) | (code[pos] & 0xff);
                    pos = pos + 1;
                }
            } else {
                len = (int) code[pos];
                pos = pos + 1;
            }
            pos = pos + len;
            
            // read the keys
            for (int i = 0; i < 8; ++i)
            {
                if (pos >= code.length)
                    throw new IllegalArgumentException("end of file at " + pos);
                if (code[pos] != 2)
                    throw new IllegalArgumentException("encountered invalid integer tag "
                        + ((int) code[pos]) + " at " + pos);
                pos = pos + 1;
                if ((code[pos] & 0x80) == 0x80) {
                    int n = (int) code[pos] & 0x7f;
                    pos = pos + 1;
                    for (i = 0; i < n; ++i) {
                        len = (len << 8) | (code[pos] & 0xff);
                        pos = pos + 1;
                    }
                } else {
                    len = (int) code[pos];
                    pos = pos + 1;
                }
                byte[] x = new byte[len];
                System.arraycopy(code, pos, x, 0, len);
                pos = pos + len;
                ints[i] = new BigInteger(x);
            }
            
        } else
            throw new IOException("invalid private key leading tag "
                    + (int) code[pos]);
        
        return new RSAPrivateCrtKeySpec(ints[0] // modulus
                                             , ints[1]   // publicExponent
                                             , ints[2]   // privateExponent
                                             , ints[3]   // primeP
                                             , ints[4]   // primeQ
                                             , ints[5]   // primeExponentP
                                             , ints[6]   // primeExponentQ
                                             , ints[7]   // crtCoefficient
                                             );
    }
}
