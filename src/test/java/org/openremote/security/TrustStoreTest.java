package org.openremote.security;

import org.testng.annotations.Test;

import java.io.File;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.UUID;

/**
 * TODO
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class TrustStoreTest
{

  @Test
  public void testAddCertBKS() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());


      char[] passwd = "foo".toCharArray();

      PrivateKeyManager privatekey = PrivateKeyManager.create(KeyManager.Storage.BKS);

      Certificate cert = privatekey.addKey("test", passwd);


      File userDir = new File(System.getProperty("user.dir"));
      File trustStorefile = new File(userDir, "truststore");
      trustStorefile.deleteOnExit();

      TrustStore trust = TrustStore.create(trustStorefile.toURI(), KeyManager.Storage.BKS);

      trust.addTrustedCertificate("mycert", cert);
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }



  @Test public void testAddCertJCEKS() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());


      char[] passwd = "foo".toCharArray();

      PrivateKeyManager privatekey = PrivateKeyManager.create(KeyManager.Storage.UBER);

      Certificate cert = privatekey.addKey("test", passwd);


      File userDir = new File(System.getProperty("user.dir"));
      File trustStorefile = new File(userDir, "truststore" + UUID.randomUUID());
      trustStorefile.deleteOnExit();

      TrustStore trust = TrustStore.create(trustStorefile.toURI(), KeyManager.Storage.JCEKS);

      trust.addTrustedCertificate("mycert", cert);
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }

}


