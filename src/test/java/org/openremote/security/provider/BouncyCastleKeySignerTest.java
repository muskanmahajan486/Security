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
package org.openremote.security.provider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.spec.ECGenParameterSpec;
import java.text.DecimalFormat;
import java.util.Date;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.openremote.base.exception.IncorrectImplementationException;
import org.openremote.security.KeyManager;
import org.openremote.security.KeySigner;
import org.openremote.security.KeySignerTest;
import org.openremote.security.PrivateKeyManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link BouncyCastleKeySigner} class.
 *
 * @author <a href = "mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class BouncyCastleKeySignerTest
{



  // SignPublicKey Tests --------------------------------------------------------------------------

  /**
   * Test self-signed RSA 2048 key with SHA-256 certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedKeyCreationWithRSAKeys() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair();

    String x500CommonName = "BouncyCastleKeySignerTest";


    // config :
    //  - SHA-256 with RSA signature algorithm
    //  - ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(
            keyPair,
            KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
            x500CommonName
        )
    );

    // should be valid immediately after creation...

    cert.checkValidity();

    Long year = TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS);
    Long minutes = TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);

    // should be valid in 5 years time (default validity is 10 years)...

    Long time = System.currentTimeMillis();
    cert.checkValidity(new Date(time + year * 5));

    // should *not* be valid in 11 years time (default validity is 10 years)...

    try
    {
      cert.checkValidity(new Date(time + year * 11));

      Assert.fail("Certificate was valid over default 10 years");
    }
    catch (CertificateExpiredException e)
    {
      // expected...
    }


    // We used RSA encryption for public-private key pair...

    Assert.assertTrue(cert.getPublicKey().getAlgorithm().equals("RSA"));
    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );

    // Issuer names should always include default organization attributes..

    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Subject for self-signed certificates should be equal to issuer...

    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + 10*year + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + 10*year - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(
        cert.getSigAlgName().equals(
            KeySigner.SignatureAlgorithm.SHA256_WITH_RSA.toString()
        )
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Test self-signed RSA 3096 key with SHA-512 certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedKeyCreationWithRSAKeysSHA512Cert() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair(3096);

    String x500CommonName = "BouncyCastleKeySignerTest";


    // config :
    //  - SHA-512 with RSA signature algorithm
    //  - ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(
            keyPair,
            KeySigner.SignatureAlgorithm.SHA512_WITH_RSA,
            x500CommonName
        )
    );

    // should be valid immediately after creation...

    cert.checkValidity();

    Long year = TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS);
    Long minutes = TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);

    // should be valid in 5 years time (default validity is 10 years)...

    Long time = System.currentTimeMillis();
    cert.checkValidity(new Date(time + year * 5));

    // should *not* be valid in 11 years time (default validity is 10 years)...

    try
    {
      cert.checkValidity(new Date(time + year * 11));

      Assert.fail("Certificate was valid over default 10 years");
    }
    catch (CertificateExpiredException e)
    {
      // expected...
    }


    // We used RSA encryption for public-private key pair...

    Assert.assertTrue(cert.getPublicKey().getAlgorithm().equals("RSA"));
    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );

    // Issuer names should always include default organization attributes..

    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Subject for self-signed certificates should be equal to issuer...

    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + 10*year + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + 10*year - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(
        cert.getSigAlgName().equals(
            KeySigner.SignatureAlgorithm.SHA512_WITH_RSA.toString()
        )
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Test self-signed RSA 4192-bit key with default signature algorithm.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedKeyWithDefaultSignatureAlgo() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair(4192);

    String x500CommonName = "BouncyCastleKeySignerTest2";


    // config :
    //  - Default RSA signature algorithm
    //  - Default ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createDefault(
            keyPair,
            x500CommonName
        )
    );

    // should be valid immediately after creation...

    cert.checkValidity();

    Long year = TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS);
    Long minutes = TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);

    // should be valid in 5 years time (default validity is 10 years)...

    Long time = System.currentTimeMillis();
    cert.checkValidity(new Date(time + year * 5));

    // should *not* be valid in 11 years time (default validity is 10 years)...

    try
    {
      cert.checkValidity(new Date(time + year * 11));

      Assert.fail("Certificate was valid over default 10 years");
    }
    catch (CertificateExpiredException e)
    {
      // expected...
    }


    // We used RSA encryption for public-private key pair...

    Assert.assertTrue(cert.getPublicKey().getAlgorithm().equals("RSA"));
    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );

    // Issuer names should always include default organization attributes..

    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Subject for self-signed certificates should be equal to issuer...

    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + 10*year + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + 10*year - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(
        cert.getSigAlgName()
            .equals
                (KeyManager.AsymmetricKeyAlgorithm.RSA.getDefaultSignatureAlgorithm().toString())
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Test self signed ECDSA 521-bit key with SHA-384 certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedCertificateWithEllipticCurves() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = generateEllipticCurveKeyPair();

    String x500CommonName = "foo";


    // default config :
    //  - default signature algo with 521-bit EC-DSA
    //  - default ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject

    X509Certificate cert = signer.signPublicKey(
        KeySigner.Configuration.createDefault(keyPair, x500CommonName)
    );

    // should be valid immediately after creation...

    cert.checkValidity();

    Long year = TimeUnit.MILLISECONDS.convert(365, TimeUnit.DAYS);

    // should be valid in 5 years time (default validity is 10 years)...

    Long time = System.currentTimeMillis();
    cert.checkValidity(new Date(time + year * 5));

    // should *not* be valid in 11 years time (default validity is 10 years)...

    try
    {
      cert.checkValidity(new Date(time + year * 11));

      Assert.fail("Certificate was valid over default 10 years");
    }
    catch (CertificateExpiredException e)
    {
      // expected...
    }


    // We used elliptic curves for public-private key pair...

    Assert.assertTrue(
        cert.getPublicKey().getAlgorithm().equals("EC"),
        "Expected 'EC', got '" + cert.getPublicKey().getAlgorithm() + "'"
    );

    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof ECPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );


    // Algorithm name should match to signature algorithm in configuration.
    // BouncyCastle reports this via ASN.1 identifier....

    Assert.assertTrue(
        cert.getSigAlgName().equals(KeySigner.DEFAULT_EC_SIGNATURE_ALGORITHM.getASN1()),
        "Expected '" + KeySigner.DEFAULT_EC_SIGNATURE_ALGORITHM.getASN1() + "', " +
        "got '" + cert.getSigAlgName() + "' instead."
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    Security.addProvider(new BouncyCastleProvider());
    cert.verify(keyPair.getPublic(), "BC");

    Security.removeProvider("BC");
  }


  /**
   * Test ECDSA 384-bit key with SHA-512 self signed certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSigned384BitKeyWithSha512SignatureAlgo() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = generate384BitEllipticCurveKeyPair();

    String x500CommonName = "bar";

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(
            keyPair,
            KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA,
            x500CommonName
        )
    );


    // We used elliptic curves for public-private key pair...

    Assert.assertTrue(
        cert.getPublicKey().getAlgorithm().equals("EC"),
        "Expected 'EC', got '" + cert.getPublicKey().getAlgorithm() + "'"
    );

    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof ECPublicKey);
    Assert.assertTrue(Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded()));


    // Algorithm name should match to signature algorithm in configuration.
    // BouncyCastle reports this via ASN.1 identifier....

    Assert.assertTrue(
        cert.getSigAlgName().equals(KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA.getASN1()),
        "Expected '" + KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA.getASN1() + "', " +
        "got '" + cert.getSigAlgName() + "' instead."
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    try
    {
      Security.addProvider(new BouncyCastleProvider());

      cert.verify(keyPair.getPublic(), "BC");
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Test self signed ECDSA 256-bit key with SHA-256 certificate.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSigned256BitEllipticCurveKeyWithSHA256SignatureAlgo() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = generate256BitEllipticCurveKeyPair();

    String x500CommonName = "acme";

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(
            keyPair,
            KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA,
            x500CommonName
        )
    );


    // We used elliptic curves for public-private key pair...

    Assert.assertTrue(
        cert.getPublicKey().getAlgorithm().equals("EC"),
        "Expected 'EC', got '" + cert.getPublicKey().getAlgorithm() + "'"
    );

    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof ECPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );


    // Algorithm name should match to signature algorithm in configuration.
    // BouncyCastle reports this via ASN.1 identifier....

    Assert.assertTrue(
        cert.getSigAlgName().equals(KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA.getASN1()),
        "Expected '" + KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA.getASN1() + "', " +
        "got '" + cert.getSigAlgName() + "' instead."
    );


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    try
    {
      Security.addProvider(new BouncyCastleProvider());

      cert.verify(keyPair.getPublic(), "BC");
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Test modified validity period in the certificate.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedKeyValidityPeriods() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair();

    String x500CommonName = "BouncyCastleKeySignerTest";


    // config :
    //  - SHA-256 with 2048-bit RSA signature algorithm
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject

    // validity set to 1 day.

    X509Certificate cert = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(

            keyPair,
            KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
            new KeySigner.Validity(1),
            x500CommonName
        )
    );

    // should be valid immediately after creation...

    cert.checkValidity();

    // should *not* be valid in 2 days time...

    Long time = System.currentTimeMillis();
    Long day = TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS);
    Long minutes = TimeUnit.MILLISECONDS.convert(1, TimeUnit.MINUTES);

    try
    {
      cert.checkValidity(new Date(time + day * 2));

      Assert.fail("Certificate was valid for more than 2 days");
    }
    catch (CertificateExpiredException e)
    {
      // expected...
    }


    // We used RSA encryption for public-private key pair...

    Assert.assertTrue(cert.getPublicKey().getAlgorithm().equals("RSA"));
    Assert.assertTrue(cert.getPublicKey().getFormat().equals("X.509"));
    Assert.assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
    Assert.assertTrue(
        Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded())
    );

    // Issuer names should always include default organization attributes...

    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Subject for self-signed certificates should be equal to issuer...

    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_ORGANIZATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_COUNTRY_SUBDIVISION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains(KeySigner.DEFAULT_X500_LOCATION)
    );
    Assert.assertTrue(
        cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName)
    );

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + day + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + day - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(cert.getSigAlgName()
        .equals(KeySigner.SignatureAlgorithm.SHA256_WITH_RSA.toString()));

    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Tests that two generated certificates do not get the same serial number.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedCertificateSerialNumber() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair();

    String x500CommonName = "BouncyCastleKeySignerTest";


    X509Certificate cert1 = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(

            keyPair,
            KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
            new KeySigner.Validity(1),
            x500CommonName
        )
    );

    X509Certificate cert2 = signer.signPublicKey(

        KeySigner.Configuration.createSelfSigned(

            keyPair,
            KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
            new KeySigner.Validity(1),
            x500CommonName
        )
    );


    // Ensure serial numbers do not match across certificates...

    Assert.assertFalse(cert1.getSerialNumber().equals(cert2.getSerialNumber()));
  }


  /**
   * Tests that generated certificate serial numbers appear to be unique.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedCertificateSerialNumbers() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    KeyPair keyPair = KeySignerTest.generateRSAKeyPair();

    String x500CommonName = "BouncyCastleKeySignerTest";

    Set<String> serialNumbers = new HashSet<String>();


    for (int i = 0; i < 100; ++i)
    {
      X509Certificate cert1 = signer.signPublicKey(

          KeySigner.Configuration.createSelfSigned(

              keyPair,
              KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
              new KeySigner.Validity(1),
              x500CommonName
          )
      );

      DecimalFormat dm = new DecimalFormat("0000000000000000000000000000000000000000");

      serialNumbers.add(dm.format(cert1.getSerialNumber()));
    }

    Assert.assertTrue(serialNumbers.size() == 100);
  }


  /**
   * Test null guard on keypair arg.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedNullKeyPair() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    String x500CommonName = "BouncyCastleKeySignerTest";

    try
    {
      signer.signPublicKey(
          KeySigner.Configuration.createDefault(null, x500CommonName)
      );

      Assert.fail("should not get here...");
    }

    catch (IncorrectImplementationException e)
    {
      // expected...
    }
  }

  /**
   * Test null guard on config arg.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedNullConfig() throws Exception
  {
    KeySigner signer = new BouncyCastleKeySigner();

    try
    {
      signer.signPublicKey(null);

      Assert.fail("should not get here...");
    }

    catch (KeySigner.SigningException e)
    {
      // expected...
    }
  }



  // Helper Methods -------------------------------------------------------------------------------


  /**
   * Generate NSA / NIST P-521 curve key pair.
   */
  private KeyPair generateEllipticCurveKeyPair() throws Exception
  {
    ECGenParameterSpec params =
        new ECGenParameterSpec(PrivateKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P521);

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

    keyGen.initialize(params);

    return keyGen.generateKeyPair();
  }

  /**
   * Generate NSA / NIST P-384 curve key pair.
   */
  private KeyPair generate384BitEllipticCurveKeyPair() throws Exception
  {
    ECGenParameterSpec params =
        new ECGenParameterSpec(PrivateKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P384);

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

    keyGen.initialize(params);

    return keyGen.generateKeyPair();
  }

  /**
   * Generate NSA / NIST P-256 curve key pair.
   */
  private KeyPair generate256BitEllipticCurveKeyPair() throws Exception
  {
    ECGenParameterSpec params =
        new ECGenParameterSpec(PrivateKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P256);

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

    keyGen.initialize(params);

    return keyGen.generateKeyPair();
  }

}


