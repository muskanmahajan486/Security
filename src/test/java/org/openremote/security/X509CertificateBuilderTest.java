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

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Unit tests for {@link X509CertificateBuilder}.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class X509CertificateBuilderTest
{

  /**
   * Basic test for setting the certificate issuer common name in configuration.
   */
  @Test public void testConfigurationIssuerName()
  {
    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration("foo");

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));
  }

  /**
   * Basic test for null guard for issuer common name in configuration constructor.
   */
  @Test public void testNullConfigurationIssuerName()
  {
    try
    {
      new X509CertificateBuilder.Configuration(null);

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
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
      new X509CertificateBuilder.Configuration("");

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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration("  foo  ");

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
                X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
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
            X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );
  }


  /**
   * Tests string trimming on provided issuer name and validity of 3 days.
   */
  @Test public void testConfiguration2IssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        new X509CertificateBuilder.Validity(3),
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_ECDSA,
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_ECDSA)
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
            X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
        )
    );
  }

  /**
   * Tests string trimming on provided issuer name.
   */
  @Test public void testConfiguration4IssuerNameTrimming()
  {
    long time = System.currentTimeMillis();

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA,
        new X509CertificateBuilder.Validity(5),
        "  foo  "
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA)
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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration("CN=foo");

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
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
            X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        new X509CertificateBuilder.Validity(10),
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));


    // Check default signature algorithm...

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM)
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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_ECDSA,
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_ECDSA)
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
            X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS, TimeUnit.DAYS) + 5000)
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

    X509CertificateBuilder.Configuration config = new X509CertificateBuilder.Configuration(
        X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_RSA,
        new X509CertificateBuilder.Validity(1),
        "CN=foo"
    );

    Assert.assertTrue(config.getIssuer().getX500Name().contains("CN=foo"));

    Assert.assertTrue(
        config.getSignatureAlgorithm()
            .equals(
        X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_RSA)
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
      new X509CertificateBuilder.Configuration("OpenRemote, Inc.");

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
      new X509CertificateBuilder.Configuration(
          X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_ECDSA,
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
      new X509CertificateBuilder.Configuration(
          X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA,
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
      new X509CertificateBuilder.Configuration(
          X509CertificateBuilder.SignatureAlgorithm.SHA384_WITH_RSA,
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
      new X509CertificateBuilder.Configuration("LOCALITY=bar");

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
      new X509CertificateBuilder.Configuration(
          X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM,
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
      new X509CertificateBuilder.Configuration(
          new X509CertificateBuilder.Validity(X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS),
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
      new X509CertificateBuilder.Configuration(
          X509CertificateBuilder.Configuration.DEFAULT_SIGNATURE_ALGORITHM,
          new X509CertificateBuilder.Validity(X509CertificateBuilder.Validity.DEFAULT_VALID_DAYS),
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
      new X509CertificateBuilder.Configuration((X509CertificateBuilder.SignatureAlgorithm)null, "foo");

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
      new X509CertificateBuilder.Configuration((X509CertificateBuilder.Validity)null, "bar");

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
    Exception e = new X509CertificateBuilder.CertificateBuilderException(
        "foo {0}", new Error("bar"), "acme");

    Assert.assertTrue(e.getCause() instanceof Error);
    Assert.assertTrue(e.getMessage().equals("foo acme"));
    Assert.assertTrue(e.getCause().getMessage().equals("bar"));
  }

  @Test public void testSignatureAlgoToString()
  {
    String sha512_rsa = X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_RSA.toString();
    String sha384_rsa = X509CertificateBuilder.SignatureAlgorithm.SHA384_WITH_RSA.toString();
    String sha256_rsa = X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_RSA.toString();
    String sha512_ecc = X509CertificateBuilder.SignatureAlgorithm.SHA512_WITH_ECDSA.toString();
    String sha384_ecc = X509CertificateBuilder.SignatureAlgorithm.SHA384_WITH_ECDSA.toString();
    String sha256_ecc = X509CertificateBuilder.SignatureAlgorithm.SHA256_WITH_ECDSA.toString();

    Assert.assertTrue(sha512_rsa.equals("SHA512withRSA"));
    Assert.assertTrue(sha384_rsa.equals("SHA384withRSA"));
    Assert.assertTrue(sha256_rsa.equals("SHA256withRSA"));

    Assert.assertTrue(sha512_ecc.equals("SHA512withECDSA"));
    Assert.assertTrue(sha384_ecc.equals("SHA384withECDSA"));
    Assert.assertTrue(sha256_ecc.equals("SHA256withECDSA"));

  }
}

