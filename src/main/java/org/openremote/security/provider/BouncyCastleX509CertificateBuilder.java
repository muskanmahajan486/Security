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
import java.math.BigInteger;
import java.text.DecimalFormat;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.openremote.security.SecurityProvider;
import org.openremote.security.X509CertificateBuilder;


/**
 * This is an implementation of {@link org.openremote.security.KeySigner} and can be used
 * to sign public keys. Signatures are created as X.509 Version 3 key certificates. <p>
 *
 * This implementation requires that a BouncyCastle security provider has been added to the
 * Java VM runtime.
 *
 * @see org.openremote.security.KeySigner
 *
 * @see java.security.Security#addProvider(java.security.Provider)
 * @see java.security.cert.X509Certificate
 *
 * @see org.bouncycastle.cert.X509v3CertificateBuilder;
 * @see org.bouncycastle.cert.X509CertificateHolder;
 * @see org.bouncycastle.operator.ContentSigner;
 *
 * @author <a href = "mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class BouncyCastleX509CertificateBuilder implements X509CertificateBuilder
{

  /**
   * Creates a public key certificate that is signed with a given private signing key. <p>
   *
   * Java encryption APIs in many places require keys that are signed with trusted authorities,
   * even in cases where third party signature authority adds little value, for example when
   * using asymmetric key encryption between two trusted services. This implementation can be used
   * to create public key certificates for those cases. <p>
   *
   * Key, signature and certificate parameters can be controlled with the
   * {@link KeySigner.Configuration} instance passed as a parameter to this call.  <p>
   *
   * @see     KeySigner.Configuration
   *
   * @param   config
   *            configuration for the certificate: issuer, validity, signature algorithm, etc.
   *
   * @return  a X.509 v3 public key certificate
   *
   * @throws  KeySigner.SigningException
   *            if creating a certificate fails for any reason
   */
  @Override public X509Certificate signPublicKey(X509CertificateBuilder.Configuration config)
      throws SigningException
  {
    if (config == null)
    {
      throw new SigningException("Implementation error: null certificate configuration.");
    }

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

