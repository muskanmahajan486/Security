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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.Provider;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.openremote.security.X509CertificateBuilder;


/**
 * A X.509 Version 3 public key certificate builder using the BouncyCastle security
 * provider and API.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class BouncyCastleX509CertificateBuilder implements X509CertificateBuilder
{

  /**
   * Creates a self-signed X.509 v3 public key certificate using BouncyCastle as security provider.
   *
   * @param keyPair
   *            public-private key pair for this certificate
   *
   * @param config
   *            configuration for the certificate: issuer, validity, signature algorithm, etc.
   *
   * @return  a self-signed X.509 v3 certificate
   *
   * @throws CertificateBuilderException
   *            if creating a certificate fails for any reason
   */
  @Override public X509Certificate createSelfSignedCertificate(KeyPair keyPair, Configuration config)
      throws CertificateBuilderException
  {
    try
    {
      Long time = System.currentTimeMillis();

      X500Name issuerName = new X500Name(config.getIssuer().getX500Name());
      X500Name subjectName = new X500Name(config.getIssuer().getX500Name());

      BigInteger serial = new BigInteger(time.toString());

      Date notBefore = new Date(config.getValidityPeriod().getNotBeforeDate().getTime());
      Date notAfter = new Date(config.getValidityPeriod().getNotAfterDate().getTime());

      X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
          issuerName, serial, notBefore, notAfter, subjectName, keyPair.getPublic()
      );

      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(
          config.getSignatureAlgorithm().toString()
      );

      Provider provider = new BouncyCastleProvider();
      contentSignerBuilder.setProvider(provider);
      
      X509CertificateHolder certHolder = certBuilder.build(
          contentSignerBuilder.build(keyPair.getPrivate())
      );

      JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
      certConverter.setProvider(provider);
      
      return certConverter.getCertificate(certHolder);
    }

    catch (OperatorCreationException e)
    {
      throw new CertificateBuilderException(
          "Unable to sign the certificate with the given private key : {0}", e, e.getMessage()
      );
    }

    catch (CertificateEncodingException e)
    {
      // should only happen if the code for certificate creation is using illegal values...

      throw new CertificateBuilderException(
          "Implementation Error -- Cannot create certificate : {0}", e, e.getMessage()
      );
    }

    catch (IllegalStateException e)
    {
      // Incorrect API usage, most likely missing fields in certificate generator...

      throw new CertificateBuilderException(
          "Implementation Error -- Cannot create certificate: {0}", e, e.getMessage()
      );
    }

    catch (CertificateException e)
    {
      // If certificate conversion from BouncyCastle X.509 to JCA X.509 certificate fails...
      
      throw new CertificateBuilderException(
          "Certification conversion error : {0}", e, e.getMessage()
      );
    }
  }

}

