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
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.openremote.exception.OpenRemoteException;

/**
 * Allows for a X.509 certificate builder plugin to be attached to
 * {@link AsymmetricKeyManager} implementation.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public interface KeySigner
{

  // Constants ------------------------------------------------------------------------------------

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
   * Used for configuring the certificate generation. This implementation provides a typed
   * interface for configuration data.
   */
  public static class Configuration
  {

    // Constants ----------------------------------------------------------------------------------

    /**
     * Default hash and asymmetric key algorithms used to sign the certificate: {@value}
     */
    public final static SignatureAlgorithm DEFAULT_SIGNATURE_ALGORITHM =
        SignatureAlgorithm.SHA384_WITH_ECDSA;


    // Instance Fields ----------------------------------------------------------------------------

    /**
     * Algorithm used for signing the certificate.
     */
    private SignatureAlgorithm signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

    /**
     * The validity duration of the certificate.
     */
    private Validity validity;

    /**
     * Certificate issuer information.
     */
    private Issuer issuer;


    // Constructors -------------------------------------------------------------------------------

    /**
     * Constructs a new certificate configuration with a given issuer name. The name can be
     * any string value, it will be formatted to as a common name in the X.500 name required
     * by the certificate. <p>
     *
     * This implementation will always include {@link KeySigner#X500_COUNTRY},
     * {@link KeySigner#X500_STATE}, {@link KeySigner#X500_LOCATION} and
     * {@link KeySigner#X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the issuer public info. <p>
     *
     * This constructor defaults to {@link #DEFAULT_SIGNATURE_ALGORITHM} as the certificate
     * signature algorithm. The default validity length of the certificate using this constructor
     * is {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of  the certificate
     * creation.
     *
     * @param issuerCommonName
     *            issuer common name as a string
     *
     * @throws IllegalArgumentException
     *            if issuer common name is empty or null
     */
    public Configuration(String issuerCommonName)
    {
      // TODO :
      //          should be more precise on the name encoding conventions, e.g. special
      //          characters ',', '=' and so on. As per definitions in for issuer name in
      //          http://tools.ietf.org/html/rfc5280#section-4.1.2.4 and the associated
      //          ITU X.501 names in http://www.itu.int/rec/T-REC-X.501-200811-S


      if (issuerCommonName == null || issuerCommonName.equals(""))
      {
        throw new IllegalArgumentException("Null or empty X.509 certificate issuer common name.");
      }

      // TODO
      //
      // Do a very basic 'common sense' check on the issuer name to ensure basic name validity.
      // As per the to-do note above, this is not complete or should be considered complete.
      // Basically we are just rejecting strings that contain '=', or comma characters to avoid
      // attribute parsing issues, right or wrong. There may be a proper way to encode these
      // characters defined in the specs. There may be other characters that should be rejected
      // or encoded.
      //                                                                                [JPL]

      issuerCommonName = issuerCommonName.trim();

      if (issuerCommonName.startsWith("CN="))
      {
        issuerCommonName = issuerCommonName.substring(3, issuerCommonName.length());
      }

      if (issuerCommonName.contains("="))
      {
        throw new IllegalArgumentException(
            "Issuer common name should not contain '=' characters : '" + issuerCommonName + "'"
        );
      }

      if (issuerCommonName.contains(","))
      {
        throw new IllegalArgumentException(
            "Issuer common name should not contain comma : '" + issuerCommonName + "'"
        );
      }

      this.validity = new Validity();

      this.signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

      try
      {
        this.issuer = new Issuer(
            new String(issuerCommonName.getBytes(), Charset.forName("UTF-8"))
        );
      }

      catch (Throwable t)
      {
        // This shouldn't really happen, UTF-8 should be available but just in case...

        AsymmetricKeyManager.securityLog.warn(
            "Unable to convert X.509 certificate issuer common name to UTF-8: {0}",
            t, t.getMessage()
        );
      }
    }

    /**
     * Constructs a new certificate configuration with a given issuer name. The name can be
     * any string value, it will be formatted to as a common name in the X.500 name required
     * by the certificate. <p>
     *
     * This implementation will always include {@link KeySigner#X500_COUNTRY},
     * {@link KeySigner#X500_STATE}, {@link KeySigner#X500_LOCATION} and
     * {@link KeySigner#X500_ORGANIZATION} as part of the X.500 distinguished name
     * of the issuer public info. <p>
     *
     * The default validity length of the certificate using this constructor is
     * {@link Validity#DEFAULT_VALID_DAYS} days, starting at the time of the certificate creation.
     *
     * @param signatureAlgo
     *            The hash and asymmetric key signature algorithms used with the certificate.
     *            See {@link AsymmetricKeyManager.KeyAlgorithm} and {@link SignatureAlgorithm}.
     *
     * @param issuerCommonName
     *            issuer common name as a string
     *
     * @throws IllegalArgumentException
     *            if issuer common name is empty or null, or if signature algorithm is null
     */
    public Configuration(SignatureAlgorithm signatureAlgo, String issuerCommonName)
    {
      this(issuerCommonName);

      if (signatureAlgo == null)
      {
        throw new IllegalArgumentException(
            "Implementation error: null certificate signature algorithm."
        );
      }

      this.signatureAlgorithm = signatureAlgo;
    }


    /**
     * Similar to {@link #Configuration(String)} except allows for specifying the validity
     * period of the certificate.
     *
     * @param valid
     *            when the certificate is considered valid
     *
     * @param issuerCommonName
     *            issuer common name as string
     *
     * @throws IllegalArgumentException
     *            if issuer common name is empty or null
     */
    public Configuration(Validity valid, String issuerCommonName)
    {
      this(issuerCommonName);

      if (valid == null)
      {
        throw new IllegalArgumentException(
            "Implementation error: certificate validity period is null"
        );
      }

      this.validity = valid;
    }


    /**
     * Similar to {@link #Configuration(String)} but also allows for specifying the signature
     * algorithm and validity period of the certificate.
     *
     * @param signatureAlgo
     *            The signature algorithm to be used with the certificate. See
     *            {@link AsymmetricKeyManager.KeyAlgorithm} and {@link SignatureAlgorithm}.
     *
     * @param valid
     *            when the certificate is considered valid
     *
     * @param issuerCommonName
     *            issuer common name as string
     *
     * @throws IllegalArgumentException
     *            if issuer common name is empty or null
     */
    public Configuration(SignatureAlgorithm signatureAlgo, Validity valid, String issuerCommonName)
    {
      this(signatureAlgo, issuerCommonName);

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
     * Returns the signature algorithm configuration of the certificate builder.
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
          X500_ORGANIZATION + "," +
          X500_COUNTRY + "," +
          X500_STATE + "," +
          X500_LOCATION + "," +
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
