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

import org.openremote.base.exception.IncorrectImplementationException;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Unit tests for {@link KeySigner}.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class KeySignerTest
{
  // Class Members --------------------------------------------------------------------------------

  /**
   * Public helper method for all tests to generate 2048 bit RSA key pair using default
   * security providers.
   */
  public static KeyPair generateRSAKeyPair() throws Exception
  {
    return generateRSAKeyPair(2048);
  }

  /**
   * Public helper method for all tests to generate RSA key pair using default security
   * providers.
   */
  public static KeyPair generateRSAKeyPair(int bitlen) throws Exception
  {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

    keyGen.initialize(bitlen);

    return keyGen.generateKeyPair();
  }



  // Tests ----------------------------------------------------------------------------------------

  /**
   * Basic test for setting the certificate issuer common name in configuration.
   */
  @Test public void testConfigurationIssuerName() throws Exception
  {
    KeySigner.Configuration config = KeySigner.Configuration.createDefault(
        KeySignerTest.generateRSAKeyPair(), "foo"
    );

    Assert.assertTrue(config.getIssuer().toX500Name().contains("CN=foo"));
  }

  /**
   * Basic test for null guard for issuer common name in configuration constructor.
   */
  @Test public void testNullConfigurationIssuerName() throws Exception
  {
    try
    {
      KeySigner.Configuration.createDefault(KeySignerTest.generateRSAKeyPair(), null);

      Assert.fail("should not get here...");
    }

    catch (IncorrectImplementationException e)
    {
      // expected...
    }
  }

  /**
   * Basic test to guard against empty issuer common names in configuration constructor.
   */
  @Test public void testEmptyConfigurationIssuerName()
  {
    try
    {
      new KeySigner.Configuration("");

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Tests string trimming on provided issuer name.
   */
  @Test public void testConfigurationIssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration("  foo  ");

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
                KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
    );


    // Check default validity period...

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(
            KeySigner.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );
  }


  /**
   * Tests string trimming on provided issuer name and validity of 3 days.
   */
  @Test public void testConfiguration2IssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        new KeySigner.Validity(3),
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
    );


    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(3, TimeUnit.DAYS) + 5000))
    );
  }


  /**
   * Tests string trimming on provided issuer name and with SHA-256 with EC-DSA signature algo.
   */
  @Test public void testConfiguration3IssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA,
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA)
    );

    // Check default validity period...

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(
            KeySigner.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );
  }

  /**
   * Tests string trimming on provided issuer name.
   */
  @Test public void testConfiguration4IssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
        new KeySigner.Validity(5),
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.SignatureAlgorithm.SHA256_WITH_RSA)
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(5, TimeUnit.DAYS) + 5000))
    );

  }

  /**
   * Test for behavior if common name 'CN' attribute type is explicitly set.
   */
  @Test public void testConfigurationIssuerNameWithAttributeType()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration("CN=foo");

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
    );


    // Check default validity period...

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(
            KeySigner.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );
  }


  /**
   * Test for behavior if common name 'CN' attribute type is explicitly set and with a custom
   * validity period.
   */
  @Test public void testConfiguration2IssuerNameWithAttributeType()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        new KeySigner.Validity(10),
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
    );


    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(10, TimeUnit.DAYS) + 5000))
    );
  }

  /**
   * Test for behavior if common name 'CN' attribute type is explicitly set and SHA-512
   * with EC DSA for signature algorithm.
   */
  @Test public void testConfiguration3IssuerNameWithAttributeType()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA,
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA)
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    // check default validity period...

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(
            KeySigner.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );

  }


  /**
   * Test for behavior if common name 'CN' attribute type is explicitly set and signature
   * algorithm is SHA-512 with RSA and validity period is one day.
   */
  @Test public void testConfiguration4IssuerNameWithAttributeType()
  {
    long time = System.currentTimeMillis();

    KeySigner.Configuration config = new KeySigner.Configuration(
        KeySigner.SignatureAlgorithm.SHA512_WITH_RSA,
        new KeySigner.Validity(1),
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        KeySigner.SignatureAlgorithm.SHA512_WITH_RSA)
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .before(
        config.getValidityPeriod().getNotAfterDate())
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotBeforeDate()
            .after(
        new Date(time - 5000))
    );

    Assert.assertTrue(
        config.getValidityPeriod().getNotAfterDate()
            .before(
        new Date(time + TimeUnit.MILLISECONDS.convert(1, TimeUnit.DAYS) + 5000))
    );

  }

  /**
   * Test for encoding special characters in issuer common name. Commas are currently rejected.
   * See the to-do tasks in the implementation for details.
   */
  @Test public void testConfigurationIssuerNameWithComma()
  {
    try
    {
      new KeySigner.Configuration("OpenRemote, Inc.");

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding special characters in issuer common name. Commas are currently rejected.
   * See the to-do tasks in the implementation for details.
   */
  @Test public void testConfiguration2IssuerNameWithComma()
  {
    try
    {
      new KeySigner.Configuration(
          KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA,
          "OpenRemote, Inc."
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding special characters in issuer common name. Commas are currently rejected.
   * See the to-do tasks in the implementation for details.
   */
  @Test public void testConfiguration3IssuerNameWithComma()
  {
    try
    {
      new KeySigner.Configuration(
          KeySigner.SignatureAlgorithm.SHA256_WITH_RSA,
          "OpenRemote, Inc."
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding special characters in issuer common name. Commas are currently rejected.
   * See the to-do tasks in the implementation for details.
   */
  @Test public void testConfiguration4IssuerNameWithComma()
  {
    try
    {
      new KeySigner.Configuration(
          KeySigner.SignatureAlgorithm.SHA384_WITH_RSA,
          "OpenRemote, Inc."
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding additional attributes with issuer common name. These are currently
   * rejected.
   */
  @Test public void testConfigurationIssuerNameAdditionalAttributes()
  {
    try
    {
      new KeySigner.Configuration("LOCALITY=bar");

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding additional attributes with issuer common name. These are currently
   * rejected.
   */
  @Test public void testConfiguration2IssuerNameAdditionalAttributes()
  {
    try
    {
      new KeySigner.Configuration(
          KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM,
          "LOCALITY=bar"
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding additional attributes with issuer common name. These are currently
   * rejected.
   */
  @Test public void testConfiguration3IssuerNameAdditionalAttributes()
  {
    try
    {
      new KeySigner.Configuration(
          new KeySigner.Validity(KeySigner.Validity.DEFAULT_VALID_DAYS),
          "LOCALITY=bar"
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test for encoding additional attributes with issuer common name. These are currently
   * rejected.
   */
  @Test public void testConfiguration4IssuerNameAdditionalAttributes()
  {
    try
    {
      new KeySigner.Configuration(
          KeySigner.Configuration.DEFAULT_SIGNATURE_ALGORITHM,
          new KeySigner.Validity(KeySigner.Validity.DEFAULT_VALID_DAYS),
          "LOCALITY=bar"
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test null guard on config signature algorithm.
   */
  @Test public void testConfigurationNullSignatureAlgo()
  {
    try
    {
      new KeySigner.Configuration((KeySigner.SignatureAlgorithm)null, "foo");

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test null guard on validity in configuration ctor.
   */
  @Test public void testConfigurationNullValidity()
  {
    try
    {
      new KeySigner.Configuration((KeySigner.Validity)null, "bar");

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Basic test on exception ctor.
   */
  @Test public void testExceptionConstructor()
  {
    Exception e = new KeySigner.SigningException(
        "foo {0}", new Error("bar"), "acme");

    Assert.assertTrue(e.getCause() instanceof Error);
    Assert.assertTrue(e.getMessage().equals("foo acme"));
    Assert.assertTrue(e.getCause().getMessage().equals("bar"));
  }

  @Test public void testSignatureAlgoToString()
  {
    String sha512_rsa = KeySigner.SignatureAlgorithm.SHA512_WITH_RSA.toString();
    String sha384_rsa = KeySigner.SignatureAlgorithm.SHA384_WITH_RSA.toString();
    String sha256_rsa = KeySigner.SignatureAlgorithm.SHA256_WITH_RSA.toString();
    String sha512_ecc = KeySigner.SignatureAlgorithm.SHA512_WITH_ECDSA.toString();
    String sha384_ecc = KeySigner.SignatureAlgorithm.SHA384_WITH_ECDSA.toString();
    String sha256_ecc = KeySigner.SignatureAlgorithm.SHA256_WITH_ECDSA.toString();

    Assert.assertTrue(sha512_rsa.equals("SHA512withRSA"));
    Assert.assertTrue(sha384_rsa.equals("SHA384withRSA"));
    Assert.assertTrue(sha256_rsa.equals("SHA256withRSA"));

    Assert.assertTrue(sha512_ecc.equals("SHA512withECDSA"));
    Assert.assertTrue(sha384_ecc.equals("SHA384withECDSA"));
    Assert.assertTrue(sha256_ecc.equals("SHA256withECDSA"));

  }
}

