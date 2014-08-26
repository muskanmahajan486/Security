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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

import org.openremote.security.provider.BouncyCastleKeySigner;

import org.testng.Assert;
import org.testng.annotations.Test;


/**
 * Unit tests for {@link PrivateKeyManager} class.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PrivateKeyManagerTest
{

  // CreateSelfSignedKey Tests --------------------------------------------------------------------

  /**
   * Basic test to demonstrate the creation of a certificate.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedKey() throws Exception
  {
    try
    {
      // Bouncycastle is required as an installed security provider for this functionality,
      // due to generating elliptic curve key which in Java 6 is not included as part of JCE.

      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      char[] keypassword = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
      String alias = "mykey";

      PrivateKeyManager keyManager = PrivateKeyManager.create();

      Certificate cert1 = keyManager.addKey(alias, keypassword, "testIssuer");

      Assert.assertTrue(cert1 instanceof X509Certificate);

      X509Certificate cert = (X509Certificate)cert1;

      Assert.assertTrue(cert.getIssuerX500Principal().getName().contains("testIssuer"));

      // TODO .. cert checks like above

      // Make sure password is erased in memory...

      for (char c : keypassword)
      {
        Assert.assertTrue(c == 0);
      }
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }

  /**
   * Certificate creation failure when required security provider is missing.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedKeyMissingProvider() throws Exception
  {
    try
    {
      PrivateKeyManager keyManager = PrivateKeyManager.create();

      char[] keypassword = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
      String alias = "mykey";

      keyManager.addKey(alias, keypassword);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  /**
   * Adds multiple new keys into the keystore manager.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testMultipleSelfSignedKeys() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      char[] keypassword2 = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '2' };
      String alias2 = "mykey2";

      PrivateKeyManager keystore = PrivateKeyManager.create(KeyManager.Storage.UBER);

      Certificate cert2 = keystore.addKey(alias2, keypassword2, "testIssuer1");

      // Make sure password is erased in memory...

      for (char c : keypassword2)
      {
        Assert.assertTrue(c == 0);
      }

      char[] keypassword3 = new char[] { 'm', 'y', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '3' };
      String alias3 = "mykey3";

      Certificate cert3 = keystore.addKey(alias3, keypassword3, "testIssuer2");

      // Make sure password is erased in memory...

      for (char c : keypassword2)
      {
        Assert.assertTrue(c == 0);
      }

      Assert.assertNotNull(cert2);
      Assert.assertNotNull(cert3);

      Assert.assertTrue(cert2 instanceof X509Certificate);
      Assert.assertTrue(cert3 instanceof X509Certificate);

      Assert.assertTrue(!cert2.equals(cert3));

      Assert.assertTrue(((X509Certificate)cert2).getIssuerX500Principal().getName().contains("testIssuer1"));
      Assert.assertTrue(((X509Certificate)cert3).getIssuerX500Principal().getName().contains("testIssuer2"));

      // TODO .. cert checks like above
      // TODO keystore size() check == 2
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }

  /**
   * Test a key alias null password which is allowed (null will be converted to
   * {@link KeyManager#EMPTY_KEY_PASSWORD}).
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedNullPasswordDefaults() throws Exception
  {
    // TODO : no longer defaults, PKCS12 storage is explicit
    try
    {
      // Default asymmetric keypair for createSelfSignedKey is elliptic curve -- this
      // requires an installed provider in Java 6 (JCE might include EC keys in Java 7)...

      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      String alias2 = "mykey2";

      PrivateKeyManager keystore = PrivateKeyManager.create(KeyManager.Storage.PKCS12);

      Certificate cert = keystore.addKey(
          alias2, null
      );

      Assert.assertNotNull(cert);
      Assert.assertTrue(cert instanceof X509Certificate);
      Assert.assertTrue(keystore.size() == 1);
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }


  /**
   * Tests default key algo in self signed keys (defined in
   * {@link PrivateKeyManager#DEFAULT_SELF_SIGNED_KEY_ALGORITHM}) which currently is EC
   * elliptic curve algorithm -- this is only available via BouncyCastle on Java 6. Testing
   * error behavior on missing provider (test may fail in Java 7 and later that includes
   * EC algorithms in JCE).
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedDefaultKeyAlgoNoProvider() throws Exception
  {
    try
    {
      String alias2 = "mykey2";

      PrivateKeyManager keystore = PrivateKeyManager.create(KeyManager.Storage.PKCS12);

      keystore.addKey(alias2, null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  /**
   * Test a key alias null password on BouncyCastle UBER storage. Null arg will be
   * converted to {@link KeyManager#EMPTY_KEY_PASSWORD} which is a non-empty char array
   * which UBER requires for keys.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedNullPasswordUberStorage() throws Exception
  {
    try
    {
      // BouncyCastle provider must be installed for UBER storage use...

      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      String alias2 = "mykey2";

      PrivateKeyManager keystore = PrivateKeyManager.create(KeyManager.Storage.UBER);

      Certificate cert = keystore.addKey(
          alias2, null
      );

      Assert.assertNotNull(cert);
      Assert.assertTrue(cert instanceof X509Certificate);
      Assert.assertTrue(keystore.size() == 1);
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }

  /**
   * Test a key alias null password with JCEKS storage and RSA keys. Null password
   * arg will be converted to {@link KeyManager#EMPTY_KEY_PASSWORD} char array (non-empty).
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedNullPasswordJCEKSStorage() throws Exception
  {
    String alias2 = "mykey2";

    PrivateKeyManager keystore = PrivateKeyManager.create(KeyManager.Storage.JCEKS);
//
//    Certificate cert = keystore.createSelfSignedKey(
//        alias2, null, new BouncyCastleKeySigner(), "testInMemoryKeyStore",
//        KeyManager.AsymmetricKeyAlgorithm.RSA
//    );

    char[] password = new char[] { '1', '2' };
    Certificate cert = keystore.addKey(alias2, password, KeyManager.AsymmetricKeyAlgorithm.RSA);

    Assert.assertNotNull(cert);
    Assert.assertTrue(cert instanceof X509Certificate);
    Assert.assertTrue(keystore.size() == 1);

    for (char c : password)
    {
      Assert.assertTrue(c == 0);
    }
  }


  /**
   * Test a keystore null key alias which should *not* be allowed.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedNullKey() throws Exception
  {
    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.addKey(null, null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....
    }
  }

  /**
   * Test a keystore empty string key alias which should *not* be allowed.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedEmptyKey() throws Exception
  {
    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.addKey("", null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....
    }
  }

//  /**
//   * Test a certificate builder null reference.
//   *
//   * @throws Exception  if test fails for any reason
//   */
//  @Test public void testSelfSignedNullCertBuilder() throws Exception
//  {
//    char[] keypassword = new char[] { 'a', 'b', 'c' };
//    String alias2 = "mykey2243";
//
//    PrivateKeyManager keystore = PrivateKeyManager.create();
//
//    try
//    {
//      keystore.createSelfSignedKey(
//          alias2, keypassword, null, "testInMemoryKeyStore-2243"
//      );
//
//      Assert.fail("should not get here...");
//    }
//
//    catch (KeyManager.KeyManagerException e)
//    {
//      // expected....
//
//      for (char c : keypassword)
//      {
//        Assert.assertTrue(c == 0);
//      }
//    }
//  }


//  /**
//   * Test a null issuer name.
//   *
//   * @throws Exception  if test fails for any reason
//   */
//  @Test public void testSelfSignedNullIssuerName() throws Exception
//  {
//    char[] keypassword = new char[] { 'f', 'd', 's', '5', '_', '1' };
//    String alias2 = "mykey5221";
//
//    PrivateKeyManager keystore = PrivateKeyManager.create();
//
//    try
//    {
//      keystore.createSelfSignedKey(
//          alias2, keypassword, new BouncyCastleKeySigner(), null
//      );
//
//      Assert.fail("should not get here...");
//    }
//
//    catch (KeyManager.KeyManagerException e)
//    {
//      // expected....
//
//      for (char c : keypassword)
//      {
//        Assert.assertTrue(c == 0);
//      }
//    }
//  }

  /**
   * Test a empty string issuer name.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testSelfSignedEmptyIssuerName() throws Exception
  {
    char[] keypassword = new char[] { 'f', 'd', 's', '5', '_', '1' };
    String alias2 = "mykey5221";

    PrivateKeyManager keystore = PrivateKeyManager.create();

    try
    {
      keystore.addKey(alias2, keypassword, "");

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected....

      for (char c : keypassword)
      {
        Assert.assertTrue(c == 0);
      }
    }
  }


   // TODO : test certificate contents

  /**
   * Tests storing of keys into an in-memory keystore format.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testInMemoryKeystore() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      char[] keypassword1 = new char[] { 'F', 'o', 'o', 'B', 'a', 'r' };
      String alias1 = "key1";

      PrivateKeyManager keyMgr = PrivateKeyManager.create(KeyManager.Storage.BKS);

      Certificate cert1 = keyMgr.addKey(alias1, keypassword1, "testIssuer");


      // TODO : these are not key passwords but master passwords...

      char[] keypassword2 = new char[] { 'F', 'o', 'o', 'b', 'a', 'r' };
      String alias2 = "key2";

      Certificate cert2 = keyMgr.addKey(alias2, keypassword2, "testIssuer2");

      char[] storePW = new char[] { 'f', 'o', 'o', 'b', 'a', 'r' };
      File dest = File.createTempFile("openremote", "tmp");
      dest.deleteOnExit();

      keyMgr.save(dest.toURI(), storePW);
      Assert.assertTrue(dest.exists());


      // Make sure the password is erased from memory...

      for (char c : storePW)
      {
        Assert.assertTrue(c == 0);
      }

      Assert.assertTrue(keyMgr.size() == 2);

      Assert.assertTrue(keyMgr.contains("key1"));
      Assert.assertTrue(keyMgr.contains("key2"));

      // check the public key certificates...

      Certificate cert = keyMgr.getCertificate("key1");

      Assert.assertTrue(cert.equals(cert1));
      Assert.assertTrue(cert.getPublicKey().equals(cert1.getPublicKey()));


      cert = keyMgr.getCertificate("key2");

      Assert.assertTrue(cert.equals(cert2));
      Assert.assertTrue(cert.getPublicKey().equals(cert2.getPublicKey()));
      Assert.assertTrue(cert.getPublicKey() instanceof ECPublicKey);
      Assert.assertTrue(
          cert.getPublicKey().getAlgorithm().equals(PrivateKeyManager.AsymmetricKeyAlgorithm.EC.name())
      );

  //    Certificate[] chain = cert.getCertificateChain();
  //
  //    Assert.assertTrue(chain.length == 1);



      // Retrieve password protected private keys...

      keypassword1 = new char[] { 'F', 'o', 'o', 'B', 'a', 'r' };

      PrivateKey privateKey = keyMgr.getKey("key1", keypassword1);
  //
  //    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
  //        "key1",
  //        new KeyStore.PasswordProtection(keypassword1)
  //    );

      Assert.assertTrue(privateKey != null);
      Assert.assertTrue(privateKey instanceof ECPrivateKey);
      Assert.assertTrue(
          privateKey.getAlgorithm().equals(KeyManager.AsymmetricKeyAlgorithm.EC.name())
      );

      keypassword2 = new char[] { 'F', 'o', 'o', 'b', 'a', 'r' };

  //    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
  //        "key2",
  //        new KeyStore.PasswordProtection(keypassword2)
  //    );

      privateKey = keyMgr.getKey("key2", keypassword2);

      Assert.assertTrue(privateKey != null);
      Assert.assertTrue(privateKey instanceof ECPrivateKey);
      Assert.assertTrue(
          privateKey.getAlgorithm().equals(KeyManager.AsymmetricKeyAlgorithm.EC.name())
      );
    }

    finally
    {
      Security.removeProvider(SecurityProvider.BC.getProviderInstance().getName());
    }
  }


  /**
   * Tests key manipulation operations.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testInMemoryKeystoreOperations() throws Exception
  {

    PrivateKeyManager keyMgr = PrivateKeyManager.create();

    // Add two keys...

    char[] keypassword = new char[] { 'a', 'C', 'm', '3'};
    String alias1 = "key1";

    keyMgr.createSelfSignedKey(
        alias1, keypassword, new BouncyCastleKeySigner(), "testIssuer"
    );

    String alias2 = "key2";

    keyMgr.createSelfSignedKey(
        alias2, new char[] {}, new BouncyCastleKeySigner(), "testIssuer2"
    );


    // Convert to keystore...

    char[] storePW = new char[] { 'f', 'o', 'o'};
    KeyStore keystore = keyMgr.save(storePW);

    Assert.assertTrue(keystore.size() == 2);
    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));


    // Add two additional keys...

    String alias3 = "key3";

    keyMgr.createSelfSignedKey(
        alias3, new char[] {}, new BouncyCastleKeySigner(), "testIssuer3"
    );

    String alias4 = "key4";

    keyMgr.createSelfSignedKey(
        alias4, new char[] {}, new BouncyCastleKeySigner(), "testIssuer4"
    );

    // Convert to keystore...

    storePW = new char[] { 'f', 'o', 'o'};
    keystore = keyMgr.save(storePW);

    Assert.assertTrue(keystore.size() == 4);

    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));
    Assert.assertTrue(keystore.containsAlias("key3"));
    Assert.assertTrue(keystore.containsAlias("key4"));



    // Add a key with existing alias... (should override)

    String alias5 = "key2";

    keyMgr.createSelfSignedKey(
        alias5, new char[] {}, new BouncyCastleKeySigner(), "testIssuer3"
    );

    String alias6 = "key6";

    keyMgr.createSelfSignedKey(
        alias6, new char[] {}, new BouncyCastleKeySigner(), "testIssuer4"
    );


    // Convert to keystore instance....

    keystore = keyMgr.save(new char[] { 0 });

    Assert.assertTrue(keystore.size() == 5, "expected 5 keys, found " + keystore.size());

    Assert.assertTrue(keystore.containsAlias("key1"));
    Assert.assertTrue(keystore.containsAlias("key2"));
    Assert.assertTrue(keystore.containsAlias("key3"));
    Assert.assertTrue(keystore.containsAlias("key4"));
    Assert.assertTrue(keystore.containsAlias("key6"));


    // retrieve password protected private key entry...

    keypassword = new char[] { 'a', 'C', 'm', '3' };

    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key1",
        new KeyStore.PasswordProtection(keypassword)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key2",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key3",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key4",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);

    entry = (KeyStore.PrivateKeyEntry)keystore.getEntry(
        "key6",
        new KeyStore.PasswordProtection(null)
    );

    Assert.assertTrue(entry.getPrivateKey() != null);
  }


  /**
   * Tests storing and loading a keystore from a file-system.
   *
   * @throws Exception  if test fails
   */
  @Test public void testFileKeyStore() throws Exception
  {
    PrivateKeyManager keyMgr = PrivateKeyManager.create();

    char[] keypassword = new char[] { 'a', 'C', 'm', '3'};
    String alias1 = "key1";

    keyMgr.createSelfSignedKey(
        alias1, keypassword, new BouncyCastleKeySigner(), "testIssuer"
    );

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    char[] storePW = new char[] { 'f', 'o', 'o'};

    keyMgr.save(f.toURI(), storePW);

    // Make sure the password is erased from memory after the API call...

    for (char c : storePW)
    {
      Assert.assertTrue(c == 0);
    }

    KeyStore loadStore = KeyStore.getInstance(PrivateKeyManager.StorageType.PKCS12.name());

    storePW = new char[] { 'f', 'o', 'o'};
    loadStore.load(new BufferedInputStream(new FileInputStream(f)), storePW);

    Assert.assertTrue(loadStore.size() == 1);
    Assert.assertTrue(loadStore.containsAlias("key1"));
  }


  /**
   * Runs basic test to ensure the key algorithm names are consistent across
   * name(), toString() and getAlgorithmName()
   */
  @Test public void testKeyAlgorithmNames()
  {
    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.name().equals(PrivateKeyManager.KeyAlgorithm.EC.toString())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.toString().equals(PrivateKeyManager.KeyAlgorithm.EC.getAlgorithmName())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.EC.getAlgorithmName().equals(PrivateKeyManager.KeyAlgorithm.EC.name())
    );


    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.name().equals(PrivateKeyManager.KeyAlgorithm.RSA.toString())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.toString().equals(PrivateKeyManager.KeyAlgorithm.RSA.getAlgorithmName())
    );

    Assert.assertTrue(
        PrivateKeyManager.KeyAlgorithm.RSA.getAlgorithmName().equals(PrivateKeyManager.KeyAlgorithm.RSA.name())
    );

  }
}

