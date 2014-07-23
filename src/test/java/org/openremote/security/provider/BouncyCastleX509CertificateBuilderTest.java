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
import java.util.Date;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openremote.security.AsymmetricKeyManager;
import org.openremote.security.X509CertificateBuilder;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link BouncyCastleKeySigner} class.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class BouncyCastleX509CertificateBuilderTest
{

  /**
   * Test self-signed RSA 2048 with SHA-256 certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedCertificateCreationWithRSAKeys() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generateRSAKeyPair();

    String x500CommonName = "BouncyCastleX509CertificateBuilderTest";


    // config :
    //  - SHA-256 with RSA signature algorithm
    //  - ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject
    //  - serial number is time of creation

    X509Certificate cert = builder.createSelfSignedCertificate(
        keyPair,
        new X509CertificateBuilder.Configuration(
            X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA,
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
    Assert.assertTrue(Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded()));

    // Issuer names should always include default organization attributes
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_ORGANIZATION));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_COUNTRY));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_STATE));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_LOCATION));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName));

    // Subject for self-signed certificates should be equal to issuer
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_ORGANIZATION));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_COUNTRY));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_STATE));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_LOCATION));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName));

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + 10*year + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + 10*year - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(cert.getSigAlgName().equals(X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA.toString()));


    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Test self signed ECDSA 521 bit with SHA-384 certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedCertificateWithEllipticCurves() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generateEllipticCurveKeyPair();

    String x500CommonName = "foo";


    // default config :
    //  - SHA-384 with 521-bit EC-DSA
    //  - ten year validity
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject
    //  - serial number is time of creation

    X509Certificate cert = builder.createSelfSignedCertificate(
        keyPair,
        new X509CertificateBuilder.Configuration(x500CommonName)
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
    Assert.assertTrue(Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded()));


    // Algorithm name should match to signature algorithm in configuration.
    // BouncyCastle reports this via ASN.1 identifier....

    Assert.assertTrue(
        cert.getSigAlgName().equals(AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384),
        "Expected '" + AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384 + "', " +
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
   * Test ECDSA 384-bit with SHA-512 self signed certificate.
   *
   * @throws Exception    if test fails
   */
  @Test public void testSelfSignedCertificateWith384BitEllipticCurves() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generate384BitEllipticCurveKeyPair();

    String x500CommonName = "bar";

    X509Certificate cert = builder.createSelfSignedCertificate(
        keyPair,
        new X509CertificateBuilder.Configuration(
            X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_ECDSA,
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
        cert.getSigAlgName().equals(AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512),
        "Expected '" + AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512 + "', " +
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
   * Test self signed ECDSA 256 bit with SHA-256 certificate.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedCertificateWith256BitEllipticCurves() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generate256BitEllipticCurveKeyPair();

    String x500CommonName = "acme";

    X509Certificate cert = builder.createSelfSignedCertificate(
        keyPair,
        new X509CertificateBuilder.Configuration(
            X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_ECDSA,
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
        cert.getSigAlgName().equals(AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256),
        "Expected '" + AsymmetricKeyManager.ASN_OID_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256 + "', " +
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
   * Test modified validity period in the certificate.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedCertificateValidityPeriods() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generateRSAKeyPair();

    String x500CommonName = "BouncyCastleX509CertificateBuilderTest";


    // config :
    //  - SHA-256 with 2048-bit RSA signature algorithm
    //  - Default issuer organization X.500 name
    //  - Self signed : issuer is same as subject
    //  - serial number is time of creation

    // validity set to 1 day.

    X509Certificate cert = builder.createSelfSignedCertificate(

        keyPair,
        new X509CertificateBuilder.Configuration(

            X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA,
            new X509CertificateBuilder.Validity(1),
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
    Assert.assertTrue(Arrays.equals(cert.getPublicKey().getEncoded(), keyPair.getPublic().getEncoded()));

    // Issuer names should always include default organization attributes
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_ORGANIZATION));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_COUNTRY));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_STATE));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains(X509CertificateBuilder.X500_LOCATION));
    Assert.assertTrue(cert.getIssuerX500Principal().getName().contains("CN=" + x500CommonName));

    // Subject for self-signed certificates should be equal to issuer
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_ORGANIZATION));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_COUNTRY));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_STATE));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains(X509CertificateBuilder.X500_LOCATION));
    Assert.assertTrue(cert.getSubjectX500Principal().getName().contains("CN=" + x500CommonName));

    // Default certificate configuration should be valid at creation...

    Assert.assertTrue(cert.getNotBefore().getTime() <= time);

    // Should be valid little before end date but not little after (5 minutes)...

    Assert.assertTrue(cert.getNotAfter().getTime() < time + day + 5*minutes);
    Assert.assertTrue(cert.getNotAfter().getTime() > time + day - 5*minutes);

    // Algorithm name should match to signature algorithm in configuration...

    Assert.assertTrue(cert.getSigAlgName()
        .equals(X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA.toString()));

    // Implementation creates V3 X.509 certificates...

    Assert.assertTrue(cert.getVersion() == 3);
    Assert.assertTrue(cert.getType().equals("X.509"));

    // verify the cert with the public key...

    cert.verify(keyPair.getPublic());
  }


  /**
   * Test null guard on keypair arg.
   *
   * @throws Exception      if test fails
   */
  @Test public void testSelfSignedNullKeyPair() throws Exception
  {
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generateEllipticCurveKeyPair();

    String x500CommonName = "BouncyCastleX509CertificateBuilderTest";

    try
    {
      X509Certificate cert = builder.createSelfSignedCertificate(
          null, new X509CertificateBuilder.Configuration(x500CommonName)
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
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
    X509CertificateBuilder builder = new BouncyCastleKeySigner();

    KeyPair keyPair = generateEllipticCurveKeyPair();

    String x500CommonName = "BouncyCastleX509CertificateBuilderTest";

    try
    {
      X509Certificate cert = builder.createSelfSignedCertificate(keyPair, null);

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }



  // Helper Methods -------------------------------------------------------------------------------

  /**
   * Generate 2048 bit RSA key pair.
   */
  private KeyPair generateRSAKeyPair() throws Exception
  {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

    keyGen.initialize(2048);

    return keyGen.generateKeyPair();
  }

  /**
   * Generate NSA / NIST P-521 curve key pair.
   */
  private KeyPair generateEllipticCurveKeyPair() throws Exception
  {
    ECGenParameterSpec params =
        new ECGenParameterSpec(AsymmetricKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P521);

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
        new ECGenParameterSpec(AsymmetricKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P384);

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
        new ECGenParameterSpec(AsymmetricKeyManager.ASN_OID_STD_CURVE_NSA_NIST_P256);

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());

    keyGen.initialize(params);

    return keyGen.generateKeyPair();
  }

}

