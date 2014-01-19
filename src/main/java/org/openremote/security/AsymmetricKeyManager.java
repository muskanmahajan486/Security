/*
 * OpenRemote, the Home of the Digital Home.
 * Copyright 2008-2014, OpenRemote Inc.
 *
 * See the contributors.txt file in the distribution for a
 * full listing of individual contributors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package org.openremote.security;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.io.InputStream;
import java.io.IOException;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Map;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.openremote.logging.Logger;
import org.openremote.logging.Hierarchy;
import org.openremote.exception.OpenRemoteException;


/**
 * This is a convenience implementation based on standard Java security architecture and its
 * management of asymmetric key pairs. It provides some helper methods for generating asymmetric
 * key pairs (for example, elliptic curves, RSA) and associated public key X.509 certificates
 * for public key infrastructure. It also provides convenience methods for persistent and
 * in-memory private key stores.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class AsymmetricKeyManager extends KeyManager
{

  // Constants ------------------------------------------------------------------------------------

  /**
   * ASN.1 OID for NSA / NIST standard curve P-521. This is equivalent to SEC 2 prime curve
   * "secp521r1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P521 = "1.3.132.0.35";

  /**
   * ASN.1 OID for NSA / NIST standard curve P-384. This is equivalent to SEC 2 prime curve
   * "secp384r1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P384 = "1.3.132.0.34";

  /**
   * ASN.1 OID for NSA / NIST standard curve P-256. This is equivalent to SEC 2 prime curve
   * "secp256r1" and ANSI X9.62 "prime256v1". OID = {@value}
   */
  public final static String ASN_OID_STD_CURVE_NSA_NIST_P256 = "1.2.840.10045.3.1.7";


  /**
   * ASN.1 OID for certificate signature algorithm 'ecdsa-with-SHA256' in certificate's
   * AlgorithmIdentifier field as defined in RFC5758 - http://tools.ietf.org/search/rfc5758.
   */
  public final static String ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

  /**
   * ASN.1 OID for certificate signature algorithm 'ecdsa-with-SHA384' in certificate's
   * AlgorithmIdentifier field as defined in RFC5758 - http://tools.ietf.org/search/rfc5758.
   */
  public final static String ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";

  /**
   * ASN.1 OID for certificate signature algorithm 'ecdsa-with-SHA512' in certificate's
   * AlgorithmIdentifier field as defined in RFC5758 - http://tools.ietf.org/search/rfc5758.
   */
  public final static String ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";


  /**
   * The default key algorithm used when generating self-signed key pairs : {@value}
   */
  public final static KeyAlgorithm DEFAULT_SELF_SIGNED_KEY_ALGORITHM = KeyAlgorithm.EC;


  /**
   * RSA key size : {@value} <p>
   *
   * This is recommended asymmetric RSA key size for classified, secret data, as per NSA Suite B.
   */
  public final static int DEFAULT_RSA_KEY_SIZE = 3072;

  /**
   * Public exponent value used in RSA algorithm (increase impacts performance): {@value)
   *
   * @see java.security.spec.RSAKeyGenParameterSpec#F4
   */
  public final static BigInteger DEFAULT_RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;



  // Enums ----------------------------------------------------------------------------------------


  /**
   * Algorithms for generating asymmetric key pairs, as defined in the document:
   * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator <p>
   *
   * Elliptic curve algorithms should be favored for any new implementations that require long
   * term, persistent signature keys. DSA is not included as an option and RSA is included to
   * support existing systems, if necessary (see http://bit.ly/1cRMTak for RSA developments). <p>
   *
   * It is worth noting that there currently exists quite a bit of debate around the quality
   * and safety properties of many standard curve specifications typically used with ECC.
   * Much of the discussion can be followed via Safecurves website at
   * http://safecurves.cr.yp.to/index.html.  <p>
   *
   * In particular, the curve specifications originating from NSA / NIST are under criticism
   * for couple of different reasons. One critique is the unexplained seed values that were
   * used to generate the curves, articulated as one of the motivations for creating
   * ECC Brainpool standard curves described here: http://bit.ly/1caBYF4   <p>
   *
   * In addition to the unclear seed value motivation, the NSA / NIST curve properties are
   * criticized for their difficult to implement properties and some safety weaknesses. Some
   * of these arguments are detailed in the presentation here: http://bit.ly/1eG1mYh
   */
  public enum KeyAlgorithm
  {

    /**
     * The default configurations for typical EC providers (i.e. SunEC provider included in Java 7
     * and BouncyCastle provider) often use standard named curves from NSA / NIST / ANSI X9.62 /
     * SECG. This implementation currently defaults to those standard curves but safer curves
     * should be adopted as soon as they're made available as named curves in the security
     * providers. BouncyCastle provider for example may be adding a safer curve 'Curve25519' for
     * example which should be used once available (see discussion here: http://bit.ly/1akHyrX). <p>
     *
     * With the default configuration, the BouncyCastle (release 1.5.0) provider will use the
     * following curves:
     *
     * <ul>
     *  <li>192-bit - NSA / NIST P-192 / ANSI X9.62 (named curve "prime192v1")</li>
     *  <li>224-bit - NSA / NIST P-224 / ANSI X9.62 (named curve "P-224")</li>
     *  <li>239-bit - ANSI X9.62 (named curve "prime239v1")</li>
     *  <li>256-bit - NSA / NIST P-256 / ANSI X9.62 (named curve "prime256v1")</li>
     *  <li>384-bit - NSA / NIST P-384 (named curve "P-384")</li>
     *  <li>521-bit - NSA / NIST P-521 (named curve "P-521")</li>
     * </ul>
     *
     * When no named curve is specified, the 239-bit curve (ANSI X9.62 prime239v1) is used.
     *
     * The SunCE provider (OpenJDK 7) will use following curves:
     *
     * <ul>
     * <li>192-bit - NSA / NIST P-192 (ASN.1 OID 1.2.840.10045.3.1.1)</li>
     * <li>224-bit - NSA / NIST P-224 (ASN.1 OID 1.3.132.0.33)</li>
     * <li>239-bit - ANSI x9.62 prime239v1</li>
     * <li>256-bit - NSA / NIST P-256 (ASN.1 OID 1.2.840.10045.3.1.7)</li>
     * <li>384-bit - NSA / NIST P-384 (ASN.1 OID 1.3.132.0.34)</li>
     * <li>521-bit - NSA / NIST P-521 (ASN.1 OID 1.3.132.0.35)</li>
     * </ul>
     *
     * When no named curve is specified, the 256-bit curve (NSA / NIST P-256) is used. Sun EC provider
     * includes also some shorter bit length curves which should not be used and some other bit
     * lengths above 256 bits not listed here but which are also defined by NSA / NIST.  <p>
     *
     * The 256-bit curve corresponding to 3072-bit asymmetric RSA key strength in combination
     * with 128-bit symmetric AES keys and SHA-2 256-bit message digests are considered adequate
     * for classified information up to secret level (as per NSA Suite B recommendation). Keys
     * with lower strength should not be used.<p>
     *
     * The 384-bit curve corresponds to 7680-bit asymmetric RSA key strength and should be used
     * in combination with 256-bit symmetric AES keys and 384-bit SHA-2 hash. This level of
     * security is currently estimated to be secure beyond year 2030 and can be used for
     * classified information up to top secret level as per NSA suite B recommendation. <p>
     */
    EC(new ECGenParameterSpec(ASN_OID_STD_CURVE_NSA_NIST_P521)),

    /**
     * RSA signature/cipher algorithm with key size as specified in
     * {@link AsymmetricKeyManager#DEFAULT_RSA_KEY_SIZE} and public exponent value as defined in
     * {@link AsymmetricKeyManager#DEFAULT_RSA_PUBLIC_EXPONENT}.  <p>
     *
     * Note the developments in solving the discrete logarithm problem (see http://bit.ly/1cRMTak)
     * and the increasing RSA key sizes that impact performance. For these reasons, elliptic
     * curves should be preferred.
     */
    RSA(new RSAKeyGenParameterSpec(DEFAULT_RSA_KEY_SIZE, DEFAULT_RSA_PUBLIC_EXPONENT));

    /**
     * Key generator algorithm configuration parameters.
     */
    private AlgorithmParameterSpec spec;

    private KeyAlgorithm(AlgorithmParameterSpec spec)
    {
      this.spec = spec;
    }
  }


  /**
   * Log categories used by this implementation.
   */
  public static enum SecurityLog implements Hierarchy
  {
    DEFAULT;

    @Override public String getCanonicalLogHierarchyName()
    {
      return "Security";
    }
  }


  // Class Members --------------------------------------------------------------------------------

  /**
   * Default logger for the security package.
   */
  protected static Logger securityLog = Logger.getInstance(SecurityLog.DEFAULT);


  /**
   * Creates a new asymmetric key manager.
   *
   * @return    key manager instance
   */
  public static AsymmetricKeyManager create()
  {
    return new AsymmetricKeyManager();
  }



  // Private Instance Fields ----------------------------------------------------------------------


  /**
   * Stores key store entries which are used when the contents of this key manager is
   * turned into a keystore implementation (in-memory, file-persisted, or otherwise).
   */
  private Map<String, KeyStoreEntry> keyEntries = new HashMap<String, KeyStoreEntry>();


  // Constructors ---------------------------------------------------------------------------------

  /**
   * Internal constructor to be used by the static builder methods.
   */
  private AsymmetricKeyManager()
  {

  }

  // TODO : add deleteKey


  // Public Instance Methods ----------------------------------------------------------------------

  /**
   * Creates an asymmetric key pair and associated self-signed X.509 public key certificate. <p>
   *
   * The key generator algorithm and algorithm configuration parameters are defined in
   * {@link #DEFAULT_SELF_SIGNED_KEY_ALGORITHM}. <p>
   *
   * The self-signed public key X.509 certificate builder is given as a method argument (this is
   * currently not provided by standard Java security architecture providers).  The default
   * configuration as specified in {@link X509CertificateBuilder.Configuration#Configuration(String)}
   * is used for validity period and signing the certificate.
   *
   * @param keyName
   *            The key name 'alias' that is used to retrieve the key information from keystore
   *
   * @param keyPassword
   *            A secret password used to retrieve the key from the keystore. Note that the
   *            character array is reset to zero bytes when this method completes.
   *
   * @param certBuilder
   *            an implementation that provides a X.509 public certificate for the public key in
   *            this asymmetric key pair
   *
   * @param issuerCommonName
   *            a X.500 common name used in the certificate, note that the other name attributes
   *            are fixed to the defaults as per the
   *            {@link X509CertificateBuilder.Configuration#Configuration(String)} implementation.
   *
   * @return  public key X.509 certificate for the generated asymmetric key pair
   *
   * @throws KeyManagerException
   *            if key generation or certificate generation fails
   */
  public Certificate createSelfSignedKey(String keyName, char[] keyPassword,
                                         X509CertificateBuilder certBuilder,
                                         String issuerCommonName) throws KeyManagerException
  {
    try
    {
      if (keyName == null || keyName.equals(""))
      {
        throw new KeyManagerException("Implementation error: Null or empty key alias is not allowed.");
      }

      if (certBuilder == null)
      {
        throw new KeyManagerException("Implementation error: null certificate builder reference.");
      }

      if (issuerCommonName == null || issuerCommonName.equals(""))
      {
        throw new KeyManagerException("Implementation error: null or empty issuer name is not allowed.");
      }

      try
      {
        KeyPair keyPair = generateKey(DEFAULT_SELF_SIGNED_KEY_ALGORITHM);

        Certificate certificate = certBuilder.createSelfSignedCertificate(
            keyPair, new X509CertificateBuilder.Configuration(issuerCommonName)
        );

        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
            keyPair.getPrivate(),
            new java.security.cert.Certificate[] { certificate }
        );

        keyEntries.put(
            keyName,
            new KeyStoreEntry(privateKeyEntry, new KeyStore.PasswordProtection(keyPassword))
        );

        return certificate;
      }

      catch (X509CertificateBuilder.CertificateBuilderException e)
      {
        throw new KeyManagerException("Certification creation failed : {0}", e, e.getMessage());
      }

      catch (KeyGeneratorException e)
      {
        throw new KeyManagerException("Key pair generation failed : {0}", e, e.getMessage());
      }
    }

    finally
    {
      // Clear the password on exit...

      if (keyPassword != null)
      {
        for (int i = 0; i < keyPassword.length; ++i)
        {
          keyPassword[i] = 0;
        }
      }
    }
  }


  /**
   * Stores the keys in this key manager in a secure keystore format. This implementation generates
   * an in-memory keystore that is not backed by a persistent storage. The format used for
   * storing the key entries is PKCS #12.
   *
   * @param password
   *            A secret password used to access the keystore contents. Note that the character
   *            array will be set to zero bytes when this method completes.
   *
   * @return    An in-memory keystore instance.
   *
   * @throws KeyManagerException
   *            if the keystore creation fails for any reason
   */
  public KeyStore save(char[] password) throws KeyManagerException
  {
    try
    {
      KeyStore keystore = instantiateKeyStore(password);

      return save(keystore, new ByteArrayOutputStream(), password);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException("Keystore could not be created : {0}", e, e.getMessage());
    }

    finally
    {
      if (password != null)
      {
        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }
    }
  }


  /**
   * Stores the keys in this key manager in a secure keystore format. This implementation generates
   * a file-based, persistent keystore which can be shared with other applications and processes.
   * The format used for storing the key entries is PKCS #12.
   *
   * @param file
   *              the file where the keystore should be saved
   *
   * @param password
   *              A secret password used to access the keystore contents. Note that the character
   *              array will be set to zero values after this method call completes.
   *
   * @return      an in-memory keystore instance
   *
   * @throws KeyManagerException
   *              if the keystore creation fails for any reason
   */
  public KeyStore save(File file, char[] password) throws KeyManagerException
  {
    if (file == null)
    {
      throw new KeyManagerException("Save failed due to null file descriptor.");
    }

    try
    {
      KeyStore keystore;

      if (exists(file))
      {
        keystore = instantiateKeyStore(file, password);
      }

      else
      {
        keystore = instantiateKeyStore(password);
     }

      BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(file));

      return save(keystore, out, password);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(
          "Cannot create the key store implementation : {0}", e, e.getMessage()
      );
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "File ''{0}'' cannot be created or opened : {1}", e, resolveFilePath(file), e.getMessage()
      );
    }

    catch (SecurityException e)
    {
      throw new KeyManagerException(
          "Security manager has denied access to file ''{0}'' : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }

    finally
    {
      if (password != null)
      {
        for (int i = 0; i < password.length; ++i)
        {
          password[i] = 0;
        }
      }
    }
  }



  // Private Instance Methods ---------------------------------------------------------------------

  /**
   * Adds the key entries of this key manager into a keystore. The keystore is saved to the given
   * output stream. The keystore can be an existing, loaded keystore or a new, empty one.
   *
   * @param keystore
   *            keystore to add keys from this key manager to
   *
   * @param out
   *            the output stream for the keystore (can be used for persisting the keystore to disk)
   *
   * @param password
   *            password to access the keystore
   *
   * @return    an in-memory keystore instance
   *
   * @throws KeyManagerException
   *            if the save operation fails
   */
  private KeyStore save(KeyStore keystore, OutputStream out, char[] password)
      throws KeyManagerException
  {
    if (password == null)
    {
      throw new KeyManagerException("Null password. Keystore must be protected with a password.");
    }

    BufferedOutputStream bout = new BufferedOutputStream(out);

    try
    {
      for (String keyAlias : keyEntries.keySet())
      {
        KeyStoreEntry entry = keyEntries.get(keyAlias);

        keystore.setEntry(keyAlias, entry.entry, entry.protectionParameter);
      }

      keystore.store(bout, password);

      return keystore;
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException("Storing the key pair failed : {0}", e, e.getMessage());
    }

    catch (IOException e)
    {
      throw new KeyManagerException(
          "Unable to write key to keystore : {1}", e, e.getMessage()
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyManagerException(
          "Security provider does not support required key store algorithm: {0}", e, e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      throw new KeyManagerException("Cannot store certificate: {0}", e, e.getMessage());
    }

    finally
    {
      if (bout != null)
      {
        try
        {
          bout.flush();
          bout.close();
        }

        catch (IOException e)
        {
          securityLog.warn("Failed to close file output stream to keystore : {0}", e, e.getMessage());
        }
      }
    }
  }


  /**
   * Checks if given file exists.
   * 
   * @param file
   *            file to check
   *
   * @return    true if file exists, false otherwise
   *
   * @throws KeyManagerException
   *            if security manager has denied access to file information
   */
  private boolean exists(final File file) throws KeyManagerException
  {
    try
    {
      return file.exists();
    }

    catch (SecurityException e)
    {
      String path = resolveFilePath(file);

      throw new KeyManagerException(
          "Security manager has prevented access to file ''{0}'' : {1}",
          e, path, e.getMessage()
      );
    }
  }

  /**
   * File utility to print file path.
   *
   * @param file
   *              file path to print
   *
   * @return      resolves to an absolute file path if allowed by the security manager, if not
   *              returns the file path as defined in the file object parameter
   */
  private String resolveFilePath(File file)
  {
    try
    {
      return file.getAbsolutePath();
    }

    catch (SecurityException e)
    {
      return file.getPath();
    }
  }


  /**
   * Instantiante an in-memory, non-persistent PKCS #12 keystore.
   *
   * @param password
   *            password to access the keystore
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyStoreException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(char[] password) throws KeyStoreException
  {
    return instantiateKeyStore(password, StorageType.PKCS12);
  }

  /**
   * Instantiate an in-memory, non-persistent keystore with a given algorithm for the storage
   * format.
   *
   * @param password
   *            password to access the keystore
   *
   * @param type
   *            the algorithm used to store the keystore data
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyStoreException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(char[] password, StorageType type) throws KeyStoreException
  {
    return getKeyStore(null, password, type);
  }

  /**
   * Loads a PKCS #12 keystore instance from an existing file.
   *
   * @param file
   *            file to load the keystore from
   *
   * @param password
   *            password to access the keystore
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyManagerException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(File file, char[] password) throws KeyManagerException
  {
    return instantiateKeyStore(file, password, StorageType.PKCS12);
  }

  /**
   * Loads a keystore instance from an existing file.
   *
   * @param file
   *            file to load the keystore from
   *
   * @param password
   *            password to access the keystore
   *
   * @param type
   *            the algorithm used to store the keystore data
   *
   * @return    in-memory keystore instance
   *
   * @throws KeyManagerException
   *            if the keystore cannot be created for any reason
   */
  private KeyStore instantiateKeyStore(File file, char[] password, StorageType type)
      throws KeyManagerException
  {
    try
    {
      BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));

      return getKeyStore(in, password, type);
    }

    catch (KeyStoreException e)
    {
      throw new KeyManagerException(
          "Keystore could not be created : {0}", e, e.getMessage()
      );
    }

    catch (FileNotFoundException e)
    {
      throw new KeyManagerException(
          "Keystore file ''{0}'' could not be created or opened : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }

    catch (SecurityException e)
    {
      throw new KeyManagerException(
          "Security manager has denied access to keystore file ''{0}'' : {1}",
          e, resolveFilePath(file), e.getMessage()
      );
    }
  }

  /**
   * Loads a key store from input stream (or creates a new, empty one). The keystore storage
   * format can be provided as a parameter.
   *
   * @param in
   *            input stream to keystore file (or null to create a new one)
   *
   * @param password
   *            shared secret (a password) used for protecting access to the keystore
   *
   * @param type
   *            the algorithm used to securely store the keystore data
   *
   * @return  an in-memory keystore instance
   *
   * @throws KeyStoreException
   *            if the provided security provider does not contain implementation for the
   *            required keystore type, or loading the keystore fails for any other reason
   */
  private KeyStore getKeyStore(InputStream in, char[] password, StorageType type)
      throws KeyStoreException
  {
    if (password == null)
    {
      throw new KeyStoreException("Null password. Keystore must be protected with a password.");
    }

    try
    {
      KeyStore keystore = KeyStore.getInstance(type.name(), DEFAULT_SECURITY_PROVIDER);
      keystore.load(in, password);

      return keystore;
    }
    catch (NoSuchAlgorithmException e)
    {
      // If the configured provider(s) do not recognize the keystore format...

      throw new KeyStoreException(
          "Required keystore algorithm '" + type.toString() + "' not found: " +
          e.getMessage(), e
      );
    }
    catch (CertificateException e)
    {
      // Can happen if any of the certificates in the store cannot be loaded...

      throw new KeyStoreException("Can't load keystore: " + e.getMessage(), e);
    }
    catch (IOException e)
    {
      // If there's an I/O problem, or if keystore has been corrupted, or if password is missing

      if (e.getCause() != null && e.getCause() instanceof UnrecoverableKeyException)
      {
        throw new KeyStoreException(
            "Cannot recover keys from keystore (was the provided password correct?) : " +
            e.getMessage(), e
        );
      }

      throw new KeyStoreException("Can't load keystore: " + e.getMessage(), e);
    }
  }


  /**
   * Generates a new asymmetric key pair using the given algorithm and algorithm parameters.
   *
   * @param keyAlgo
   *            algorithm for the key generator
   *
   * @return generated key pair
   *
   * @throws KeyGeneratorException
   *            in case any errors in key generation
   */
  private KeyPair generateKey(KeyAlgorithm keyAlgo) throws KeyGeneratorException
  {
    try
    {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgo.toString(), DEFAULT_SECURITY_PROVIDER);
      keyGen.initialize(keyAlgo.spec);

      return keyGen.generateKeyPair();
    }

    catch (InvalidAlgorithmParameterException e)
    {
      throw new KeyGeneratorException(
          "Invalid algorithm parameter in {0} : {1}", e, keyAlgo, e.getMessage()
      );
    }

    catch (NoSuchAlgorithmException e)
    {
      throw new KeyGeneratorException(
          "No security provider found for {0} : {1}", e, keyAlgo, e.getMessage()
      );
    }
  }




  // Nested Classes -------------------------------------------------------------------------------


  /**
   * Convenience class to hold keystore entry and its protection parameter as single entity in
   * collections.
   */
  private static class KeyStoreEntry
  {
    private KeyStore.Entry entry;
    private KeyStore.ProtectionParameter protectionParameter;

    private KeyStoreEntry(KeyStore.Entry entry, KeyStore.ProtectionParameter param)
    {
      this.entry = entry;
      this.protectionParameter = param;
    }
  }



  /**
   * Exception type for the public API of this class to indicate errors.
   */
  public static class KeyManagerException extends OpenRemoteException
  {
    private KeyManagerException(String msg)
    {
      super(msg);
    }

    private KeyManagerException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }

  /**
   * Specific (internal -- shows up as root cause) exception type for asymmetric
   * key pair generation.
   */
  public static class KeyGeneratorException extends OpenRemoteException
  {
    private KeyGeneratorException(String msg, Throwable cause, Object... params)
    {
      super(msg, cause, params);
    }
  }
}

