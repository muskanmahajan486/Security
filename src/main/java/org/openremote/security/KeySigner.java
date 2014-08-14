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

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.openremote.base.exception.IncorrectImplementationException;
import org.openremote.base.exception.OpenRemoteException;

/**
 * Allows for a X.509 certificate builder plugin to be attached to
 * {@link AsymmetricKeyManager} implementation.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public interface KeySigner
{

  // Constants ------------------------------------------------------------------------------------

  /**
   * Default organization name used in public key certificate's X500 issuer name if nothing else
   * is provided. This default organization name is also used when self-signing public keys, unless
   * other values are provided. <p>
   *
   * X.500 organization name for OpenRemote, Inc : {@value}
   *
   * @see Configuration#createDefault(java.security.KeyPair, String)
   * @see Configuration#createSelfSigned(java.security.KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static String DEFAULT_X500_ORGANIZATION = "O=OpenRemote Inc.";

  /**
   * Default two-character ISO-3166 country identifier used in public key certificate's X500 issuer
   * name if nothing else is provided. This default country identifier is also used when
   * self-signing public keys, unless other values are provided. <p>
   *
   * X.500 country code (ISO-3166) for OpenRemote, Inc : {@value}
   *
   * @see Configuration#createDefault(java.security.KeyPair, String)
   * @see Configuration#createSelfSigned(java.security.KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static String DEFAULT_X500_COUNTRY   = "C=US";

  /**
   * Default country subdivision identifier used in public key certificate's X500 issuer
   * name if nothing else is provided. This default country subdivision identifier is also used
   * when self-signing public keys, unless other values are provided. <p>
   *
   * X.500 country subdivision code (ISO-3166) for OpenRemote, Inc : {@value}
   *
   * @see Configuration#createDefault(java.security.KeyPair, String)
   * @see Configuration#createSelfSigned(java.security.KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static String DEFAULT_X500_COUNTRY_SUBDIVISION = "ST=US-GA";

  /**
   * Default location attribute used in public key certificate's X500 issuer name if nothing else
   * is provided. This default location attribute is also used when self-signing public keys,
   * unless other values are provided. <p>
   *
   * X.500 location for OpenRemote, Inc : {@value}
   *
   * @see Configuration#createDefault(java.security.KeyPair, String)
   * @see Configuration#createSelfSigned(java.security.KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static String DEFAULT_X500_LOCATION  = "L=Atlanta";



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
   * ASN.1 OID for certificate signature algorithm 'sha256WithRSAEncryption' as defined in
   * RFC5698 -- http://tools.ietf.org/html/rfc5698.
   */
  public final static String ASN_OID_SHA256_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.11";

  /**
   * ASN.1 OID for certificate signature algorithm 'sha384WithRSAEncryption' as defined in
   * RFC5698 -- http://tools.ietf.org/html/rfc5698.
   */
  public final static String ASN_OID_SHA384_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.12";

  /**
   * ASN.1 OID for certificate signature algorithm 'sha512WithRSAEncryption' as defined in
   * RFC5698 -- http://tools.ietf.org/html/rfc5698.
   */
  public final static String ASN_OID_SHA512_WITH_RSA_ENCRYPTION = "1.2.840.113549.1.1.13";



  /**
   * Default certificate signature algorithm used with elliptic curve encryption keys, if
   * nothing else is specified: {@value}
   *
   * @see Configuration#createSelfSigned(KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static SignatureAlgorithm DEFAULT_EC_SIGNATURE_ALGORITHM =
      SignatureAlgorithm.SHA384_WITH_ECDSA;

  /**
   * Default certificate signature algorithm used with RSA encryption keys, if nothing else is
   * specified: {@value}
   *
   * @see Configuration#createSelfSigned(KeyPair, KeySigner.SignatureAlgorithm, String)
   */
  public final static SignatureAlgorithm DEFAULT_RSA_SIGNATURE_ALGORITHM =
      SignatureAlgorithm.SHA384_WITH_RSA;



  // Interface Definition -------------------------------------------------------------------------


  /**
   * Signs a public key and generates a signature certificate for the said key.
   *
   * @param config
   *            certificate configuration, see {@link KeySigner.Configuration}
   *
   * @return  a X.509 certificate
   *
   * @throws KeySigner.SigningException
   *            if creation of certificate fails for any reason
   */
  X509Certificate signPublicKey(Configuration config) throws SigningException;




  // Nested Classes -------------------------------------------------------------------------------

  /**
   * Used for configuring the key signing strategy. This implementation provides a typed
   * interface for configuration data.
   */
  public static class Configuration
  {

    // Class Members ------------------------------------------------------------------------------


    /**
     * Creates a default configuration for key signing.
     *
     * This configuration uses all default settings which assumes a self-signed key -- they key
     * pair should contain a private key and it's corresponding public key. The private key is
     * used to sign its own public key, creating a self-signed key pair. <p>
     *
     * This configuration will always include {@link KeySigner#DEFAULT_X500_COUNTRY},
     * {@link KeySigner#DEFAULT_X500_COUNTRY_SUBDIVISION}, {@link KeySigner#DEFAULT_X500_LOCATION}
     * and {@link KeySigner#DEFAULT_X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the certificate issuer and subject public info. <p>
     *
     * The signature algorithm is chosen from default algorithms defined in
     * {@link KeySigner#DEFAULT_EC_SIGNATURE_ALGORITHM} and
     * {@link KeySigner#DEFAULT_RSA_SIGNATURE_ALGORITHM} constants, depending whether the given
     * key pair parameter contains RSA or elliptic curve key pair. <p>
     *
     * The default validity length of the certificate using this constructor is
     * {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of the certificate creation.
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param issuerCommonName
     *            A common name used in the certificate for issuer and subject. The common name can
     *            be any string value, it will be formatted to as a common name attribute in the
     *            X.500 name required by the public key certificate. <p>
     *
     * @see #createDefault(java.security.KeyPair, String)
     *
     * @return    a new key signature configuration
     */
    public static Configuration createDefault(KeyPair keyPair, String issuerCommonName)
    {
      return new Configuration(keyPair, issuerCommonName);
    }

    /**
     * Creates a configuration for key signing.
     *
     * This configuration uses default settings which assumes a self-signed key but allows
     * signature algorithm to be specified as an argument. The key pair should contain a private
     * key and it's corresponding public key. The private key is used to sign its own public key,
     * creating a self-signed key pair. <p>
     *
     * This configuration will always include {@link KeySigner#DEFAULT_X500_COUNTRY},
     * {@link KeySigner#DEFAULT_X500_COUNTRY_SUBDIVISION}, {@link KeySigner#DEFAULT_X500_LOCATION}
     * and {@link KeySigner#DEFAULT_X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the certificate issuer and subject public info. <p>
     *
     * The signature algorithm is chosen from default algorithms defined in
     * {@link KeySigner#DEFAULT_EC_SIGNATURE_ALGORITHM} and
     * {@link KeySigner#DEFAULT_RSA_SIGNATURE_ALGORITHM} constants, depending whether the given
     * key pair parameter contains RSA or elliptic curve key pair. <p>
     *
     * The default validity length of the certificate using this constructor is
     * {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of the certificate creation.
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param signatureAlgorithm
     *            The algorithm for the signature which should match the signing keys algorithm,
     *            see {@link SignatureAlgorithm}
     *
     * @param issuerCommonName
     *            A common name used in the certificate for issuer and subject. The common name can
     *            be any string value, it will be formatted to as a common name attribute in the
     *            X.500 name required by the public key certificate. <p>
     *
     * @see #createDefault(KeyPair, String)
     *
     * @return    a new key signature configuration
     */
    public static Configuration createSelfSigned(KeyPair keyPair,
                                                 SignatureAlgorithm signatureAlgorithm,
                                                 String issuerCommonName)
    {
      return new Configuration(keyPair, signatureAlgorithm, issuerCommonName);
    }

    /**
     * Creates a configuration for key signing.
     *
     * This configuration uses default settings which assumes a self-signed key but allows
     * signature algorithm and certification validity to be specified as an argument. The key pair
     * should contain a private key and it's corresponding public key. The private key is used to
     * sign its own public key, creating a self-signed key pair. <p>
     *
     * This configuration will always include {@link KeySigner#DEFAULT_X500_COUNTRY},
     * {@link KeySigner#DEFAULT_X500_COUNTRY_SUBDIVISION}, {@link KeySigner#DEFAULT_X500_LOCATION}
     * and {@link KeySigner#DEFAULT_X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the certificate issuer and subject public info. <p>
     *
     * The signature algorithm is chosen from default algorithms defined in
     * {@link KeySigner#DEFAULT_EC_SIGNATURE_ALGORITHM} and
     * {@link KeySigner#DEFAULT_RSA_SIGNATURE_ALGORITHM} constants, depending whether the given
     * key pair parameter contains RSA or elliptic curve key pair. <p>
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param signatureAlgorithm
     *            The algorithm for the signature which should match the signing keys algorithm,
     *            see {@link SignatureAlgorithm}
     *
     * @param validity
     *            The validity period for the generated signature certificate, see
     *            {@link Validity}
     *
     * @param issuerCommonName
     *            A common name used in the certificate for issuer and subject. The common name can
     *            be any string value, it will be formatted to as a common name attribute in the
     *            X.500 name required by the public key certificate. <p>
     *
     * @see #createDefault(KeyPair, String)
     *
     * @return    a new key signature configuration
     */
    public static Configuration createSelfSigned(KeyPair keyPair,
                                                 SignatureAlgorithm signatureAlgorithm,
                                                 Validity validity,
                                                 String issuerCommonName)
    {
      return new Configuration(keyPair, signatureAlgorithm, validity, issuerCommonName);
    }


    // Instance Fields ----------------------------------------------------------------------------

    /**
     * The private signing key used for signing the public key.
     */
    private PrivateKey privateSigningKey;

    /**
     * The public key to sign.
     */
    private PublicKey publicKey;

    /**
     * Algorithm used for signing the certificate.
     */
    private SignatureAlgorithm signatureAlgorithm;

    /**
     * The validity duration of the certificate.
     */
    private Validity validity;

    /**
     * Certificate issuer information.
     */
    private Issuer issuer;

    /**
     * Certificate subject information.
     */
    private Subject subject;


    // Constructors -------------------------------------------------------------------------------

    /**
     * Constructs a new key signing configuration.
     *
     * This configuration uses all default settings which assumes a self-signed key -- they key
     * pair should contain a private key and it's corresponding public key. The private key is
     * used to sign its own public key, creating a self-signed key pair. <p>
     *
     * The self-signing is also reflected in the public key certificate. The certificate issuer
     * X500 name is equal to the subject. Also the issuer/subject name uses default X500 name
     * attributes, except for the issuer common name that can be given as a parameter. <p>
     *
     * The common name can be any string value, it will be formatted to as a common name
     * attribute in the X.500 name required by the public key certificate. <p>
     *
     * This constructor will always include {@link KeySigner#DEFAULT_X500_COUNTRY},
     * {@link KeySigner#DEFAULT_X500_COUNTRY_SUBDIVISION}, {@link KeySigner#DEFAULT_X500_LOCATION}
     * and {@link KeySigner#DEFAULT_X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the certificate issuer and subject public info. <p>
     *
     * The signature algorithm is chosen from default algorithms defined in
     * {@link KeySigner#DEFAULT_EC_SIGNATURE_ALGORITHM} and
     * {@link KeySigner#DEFAULT_RSA_SIGNATURE_ALGORITHM} constants, depending whether the given
     * key pair parameter contains RSA or elliptic curve key pair. <p>
     *
     * The default validity length of the certificate using this constructor is
     * {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of the certificate creation.
     *
     *
     * @see #createDefault(KeyPair, String)
     * @see #Configuration(KeyPair, KeySigner.SignatureAlgorithm, KeySigner.Validity, String)
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param commonName
     *            common name attribute used in the public key certificate's issuer and subject
     *            X500 names
     *
     * @throws IncorrectImplementationException
     *            if key pair, keys or common name is empty or null; if key encryption algorithm
     *            does not have a matching signature algorithm
     */
    private Configuration(KeyPair keyPair, String commonName)
    {
      if (keyPair == null)
      {
        throw new IncorrectImplementationException(
            "Configuration key pair is null."
        );
      }

      if (keyPair.getPublic() == null)
      {
        throw new IncorrectImplementationException(
            "Configuration public key is null."
        );
      }

      if (keyPair.getPrivate() == null)
      {
        throw new IncorrectImplementationException(
            "Configuation private key is null."
        );
      }

      if (commonName == null || commonName.equals(""))
      {
        throw new IncorrectImplementationException(
            "Null or empty X.509 certificate common name attribute."
        );
      }


      this.privateSigningKey = keyPair.getPrivate();
      this.publicKey = keyPair.getPublic();
      this.validity = new Validity();


      // Attempt to convert public key's encryption algorithm into a known (or defined for
      // our implementation) encryption algorithm...

      try
      {
        KeyManager.AsymmetricKeyAlgorithm keyAlgorithm =
            KeyManager.AsymmetricKeyAlgorithm.valueOf(this.publicKey.getAlgorithm());

        this.signatureAlgorithm = keyAlgorithm.getDefaultSignatureAlgorithm();
      }

      catch (IllegalArgumentException exception)
      {
        throw new IncorrectImplementationException(
            "No support defined for '{0}' encryption key algorithm.",
            this.publicKey.getAlgorithm()
        );
      }

      try
      {
        this.issuer = new Issuer(
            new String(parseCommonName(commonName).getBytes(), Charset.forName("UTF-8"))
        );
      }

      catch (SigningException exception)
      {
        // thrown by parseCommonName above...

        throw new IncorrectImplementationException(
            "Cannot parse X.500 common name '{0}' : {1}", exception,
            commonName, exception.getMessage()
        );
      }

      catch (Throwable throwable)
      {
        // This shouldn't really happen, UTF-8 should be available but just in case...

        throw new IncorrectImplementationException(
            "Unable to convert X.509 certificate common name to UTF-8: {0}", throwable,
            throwable.getMessage()
        );
      }

      this.subject = new Subject(this.issuer.toX500Name());
    }


    /**
     * Constructs a new key signing configuration. This constructor allows a specific signature
     * algorithm to be configured.
     *
     * This configuration assumes a self-signed key -- they key pair should contain a private key
     * and it's corresponding public key. The private key is used to sign its own public key,
     * creating a self-signed key pair. <p>
     *
     * The self-signing is also reflected in the public key certificate. The certificate issuer
     * X500 name is equal to the subject. Also the issuer/subject name uses default X500 name
     * attributes, except for the issuer common name that can be given as a parameter. <p>
     *
     * The common name can be any string value, it will be formatted to as a common name
     * attribute in the X.500 name required by the public key certificate. <p>
     *
     * This constructor will always include {@link KeySigner#DEFAULT_X500_COUNTRY},
     * {@link KeySigner#DEFAULT_X500_COUNTRY_SUBDIVISION}, {@link KeySigner#DEFAULT_X500_LOCATION}
     * and {@link KeySigner#DEFAULT_X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the certificate issuer and subject public info. <p>
     *
     * The default validity length of the certificate using this constructor is
     * {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of the certificate creation.
     *
     * @see #createSelfSigned(KeyPair, KeySigner.SignatureAlgorithm, String)
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param signatureAlgo
     *            The hash and asymmetric key signature algorithms used with the certificate.
     *            The chosen signature algorithm must be compatible with the encryption
     *            algorithm of the given key pair. See
     *            {@link PrivateKeyManager.AsymmetricKeyAlgorithm} and
     *            {@link KeySigner.SignatureAlgorithm}.
     *
     * @param commonName
     *            common name attribute used in the public key certificate's issuer and subject
     *            X500 names
     *
     * @throws IncorrectImplementationException
     *            if key pair, keys, signature algorithm or common name is empty or null;
     *            if key encryption algorithm does not have a matching signature algorithm
     */
    private Configuration(KeyPair keyPair, SignatureAlgorithm signatureAlgo, String commonName)
    {
      this(keyPair,  commonName);

      if (signatureAlgo == null)
      {
        throw new IncorrectImplementationException(
            "Implementation error: null certificate signature algorithm."
        );
      }

      this.signatureAlgorithm = signatureAlgo;
    }


    /**
     * Similar to {@link #Configuration(KeyPair, String)} except allows for specifying the validity
     * period of the certificate.
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param valid
     *            when the certificate is considered valid
     *
     * @param commonName
     *            common name attribute used in the public key certificate's issuer and subject
     *            X500 names
     *
     * @throws IncorrectImplementationException
     *            if key pair, keys, validity or common name is empty or null;
     *            if key encryption algorithm does not have a matching signature algorithm
     */
    private Configuration(KeyPair keyPair, Validity valid, String commonName)
    {
      this(keyPair, commonName);

      if (valid == null)
      {
        throw new IncorrectImplementationException(
            "Implementation error: certificate validity period is null"
        );
      }

      this.validity = valid;
    }


    /**
     * Similar to {@link #Configuration(KeyPair, String)} but also allows for specifying the
     * signature algorithm and validity period of the certificate.
     *
     * @param keyPair
     *            A pair of private and its corresponding public key. The private key is used
     *            to self-sign its public key.
     *
     * @param signatureAlgo
     *            The hash and asymmetric key signature algorithms used with the certificate.
     *            The chosen signature algorithm must be compatible with the encryption
     *            algorithm of the given key pair. See
     *            {@link PrivateKeyManager.AsymmetricKeyAlgorithm} and
     *            {@link KeySigner.SignatureAlgorithm}.
     *
     * @param valid
     *            when the certificate is considered valid
     *
     * @param commonName
      *            common name attribute used in the public key certificate's issuer and subject
      *            X500 names
      *
      * @throws IncorrectImplementationException
      *            if key pair, keys, signature algorithm, validity or common name is empty or null;
      *            if key encryption algorithm does not have a matching signature algorithm
     */
    private Configuration(KeyPair keyPair, SignatureAlgorithm signatureAlgo,
                          Validity valid, String commonName)
    {
      this(keyPair, signatureAlgo, commonName);


      if (valid == null)
      {
        throw new IncorrectImplementationException(
            "Implementation error: null certificate validity."
        );
      }

      this.validity = valid;
    }



    // Public Instance Methods --------------------------------------------------------------------

    /**
     * Returns the X.500 name of the certificate issuer.
     *
     * @return  issuer X.500 distinguished name
     */
    public Issuer getIssuer()
    {
      return issuer;
    }

    /**
     * Returns the X.500 name of the certificate subject.
     *
     * @return  subject X.500 distinguished name
     */
    public Subject getSubject()
    {
      return subject;
    }

    /**
     * Returns the public key to be signed.
     *
     * @return  public key which will be signed
     */
    public PublicKey getPublicKey()
    {
      return publicKey;
    }

    /**
     * Returns the private key used for signing the public key.
     *
     * @see #getPublicKey()
     *
     * @return  private key used for signing
     */
    public PrivateKey getPrivateSigningKey()
    {
      return privateSigningKey;
    }

    /**
     * Returns the signature algorithm configuration of the key signer.
     *
     * @return  certificate signature algorithm
     */
    public SignatureAlgorithm getSignatureAlgorithm()
    {
      return signatureAlgorithm;
    }

    /**
     * Returns the validity length of the certificate in milliseconds
     *
     * @return    the length of how long the certificate remains valid in milliseconds
     */
    public Validity getValidityPeriod()
    {
      return validity;
    }


    // Private Instance Methods -------------------------------------------------------------------

    private String parseCommonName(String name) throws SigningException
    {
      // TODO :
      //          should be more precise on the name encoding conventions, e.g. special
      //          characters ',', '=' and so on. As per definitions in for issuer name in
      //          http://tools.ietf.org/html/rfc5280#section-4.1.2.4 and the associated
      //          ITU X.501 names in http://www.itu.int/rec/T-REC-X.501-200811-S
      //
      // Do a very basic 'common sense' check on the issuer name to ensure basic name validity.
      // Basically we are just rejecting strings that contain '=', or comma characters to avoid
      // attribute parsing issues, right or wrong. There may be a proper way to encode these
      // characters defined in the specs. There may be other characters that should be rejected
      // or encoded.
      //                                                                                [JPL]

      name = name.trim();

      if (name.startsWith("CN="))
      {
        name = name.substring(3, name.length());
      }

      if (name.contains("="))
      {
        throw new SigningException(
            "Common name attribute should not contain '=' characters : '" + name + "'"
        );
      }

      if (name.contains(","))
      {
        throw new SigningException(
            "Common name attribute should not contain comma : '" + name + "'"
        );
      }

      return name;
    }

  }



  /**
   * Type safe signature algorithm names as per the Java Cryptography Architecture and
   * defined in: <p>>
   *
   * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
   *
   * <p>
   *
   * SHA1 based algorithms are not included due to possible vulnerabilities. SHA-2 family
   * is included as 256-bit, 384-bit and 512-bit variants.
   */
  public static enum SignatureAlgorithm
  {

    /**
     * SHA-2 256-bit secure hash with elliptic curve digital signature algorithm. Recommended
     * strength for classified secret information when used in combination with a 256-bit
     * elliptic curve (as per NSA suite B recommendation). <p>
     *
     * See {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA256_WITH_ECDSA("SHA256withECDSA"),

    /**
     * SHA-2 384-bit secure hash with elliptic curve digital signature algorithm. Recommended
     * strength for classified top secret information when used in combination with a 384-bit
     * elliptic curve (as per NSA suite B recommendation). <p>
     *
     * See {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA384_WITH_ECDSA("SHA384withECDSA"),

    /**
     * SHA-2 512-bit secure has with elliptic curve digital signature algorithm.
     * <p>
     * See {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA512_WITH_ECDSA("SHA512withECDSA"),

    /**
     * SHA-2 256-bit secure hash with RSA encryption keys. An elliptic curve
     * should be preferred over RSA but this option is supported here for compatibility. See
     * {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA256_WITH_RSA("SHA256withRSA"),

    /**
     * SHA-2 384-bit secure hash with RSA encryption keys. An elliptic curve should be preferred
     * over RSA but this option is supported here for compatibility.
     * See {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA384_WITH_RSA("SHA384withRSA"),

    /**
     * SHA-2 512-bit secure hash with RSA encryption keys. An elliptic curve
     * should be preferred over RSA but this option is supported here for compatibility. See
     * {@link AsymmetricKeyManager.KeyAlgorithm} for additional details.
     */
    SHA512_WITH_RSA("SHA512withRSA");


    /**
     * The signature algorithm
     */
    private String algorithmName;


    private SignatureAlgorithm(String algorithmName)
    {
      this.algorithmName = algorithmName;
    }

    /**
     * Returns the signature algorithm name as string as required by the Java security API.
     *
     * @return  signature algorithm name
     */
    @Override public String toString()
    {
      return algorithmName;
    }
  }


  /**
   * Defines an X.500 compatible issuer name for a certificate. <p>
   *
   * Organization name, country, state and location are fixed, only the common name can be
   * specified with this implementation. Therefore, a common name value 'foo' will yield: <p>
   *
   * <tt>O=[X500_ORGANIZATION],C=[X500_COUNTRY],ST=[X500_STATE],L=[X500_LOCATION],CN=foo</tt> </p>
   */
  public static class Issuer
  {
    /**
     * X.500 name for certificate issuer.
     */
    private String x500Name;

    /**
     * Constructs a new issuer information.
     *
     * @param commonName
     *            a common name for the issuer X.500 name
     */
    public Issuer(String commonName)
    {
      this.x500Name =
          DEFAULT_X500_ORGANIZATION + "," +
          DEFAULT_X500_COUNTRY + "," +
          DEFAULT_X500_COUNTRY_SUBDIVISION + "," +
          DEFAULT_X500_LOCATION + "," +
          "CN=" + commonName;
    }

    /**
     * Returns an X.500 formatted name of this issuer.
     *
     * @return X.500 name with organization, country, state, location and common name attributes
     */
    public String getX500Name()
    {
      return x500Name;
    }
  }


  /**
   * Defines the validity period of a certifcate, from begin date to end date.
   */
  public static class Validity
  {

    // Constants ----------------------------------------------------------------------------------

    /**
     * Default certificate validity period in days : {@value}
     */
    public final static long DEFAULT_VALID_DAYS = TimeUnit.DAYS.toDays(365 * 10);


    // Instance Fields ----------------------------------------------------------------------------

    /**
     * Date from which the certificate is valid.
     */
    private Date notBeforeDate;

    /**
     * Date after which the certificate will not be valid.
     */
    private Date notAfterDate;



    // Constructors -------------------------------------------------------------------------------

    /**
     * Defines a default validity of {@link #DEFAULT_VALID_DAYS} days starting from the time
     * of creation of this validity configuration object.
     */
    private Validity()
    {
      this(DEFAULT_VALID_DAYS);
    }

    /**
     * Defines a validity period to a given number of days starting from the time of creation
     * of this validity configuration object.
     *
     * @param days
     *            number of days the certificate should be considered valid
     */
    public Validity(long days)
    {
      Long time = System.currentTimeMillis();

      this.notBeforeDate = new Date(time - 1000);
      this.notAfterDate = new Date(time + TimeUnit.MILLISECONDS.convert(days, TimeUnit.DAYS));
    }

    /**
     * Defines validity constraints of a certificate between given before and after dates.
     *
     * @param notBefore
     *            the date before which the certificate will not be valid
     *
     * @param notAfter
     *            the date after which the certificate will not be valid
     */
    public Validity(Date notBefore, Date notAfter)
    {
      this.notBeforeDate = notBefore;
      this.notAfterDate = notAfter;
    }


    // Public Instance Methods --------------------------------------------------------------------

    /**
     * Returns the date representing the begin date of the certificate validity.
     *
     * @return  date before which the certifate is not valid
     */
    public Date getNotBeforeDate()
    {
      return notBeforeDate;
    }

    /**
     * Returns the date representing the end date of the certificate validity.
     *
     * @return  date after which the certificate is not valid
     */
    public Date getNotAfterDate()
    {
      return notAfterDate;
    }
  }


  /**
   * Checked exception type for certificate builder errors.
   */
  public static class SigningException extends OpenRemoteException
  {
    /**
     * Constructs a new exception with a give message, root cause exception and message
     * parameters.
     *
     * @param msg
     *            message (formatted according to {@link java.text.MessageFormat} API)
     */
    public SigningException(String msg)
    {
      super(msg);
    }

    /**
     * Constructs a new exception with a give message, root cause exception and message
     * parameters.
     *
     * @param msg
     *            message (formatted according to {@link java.text.MessageFormat} API)
     *
     * @param params
     *            message format parameters
     */
    public SigningException(String msg, Object... params)
    {
      super(msg, params);
    }

    /**
     * Constructs a new exception with a give message, root cause exception and message
     * parameters.
     *
     * @param msg
     *            message (formatted according to {@link java.text.MessageFormat} API)
     *
     * @param throwable
     *            root cause
     */
    public SigningException(String msg, Throwable throwable)
    {
      super(msg, throwable);
    }

    /**
     * Constructs a new exception with a give message, root cause exception and message
     * parameters.
     *
     * @param msg
     *            message (formatted according to {@link java.text.MessageFormat} API)
     *
     * @param throwable
     *            root cause
     *
     * @param params
     *            message format parameters
     */
    public SigningException(String msg, Throwable throwable, Object... params)
    {
      super(msg, throwable, params);
    }

  }

}
