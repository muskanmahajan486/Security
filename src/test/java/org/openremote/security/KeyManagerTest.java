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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.Assert;
import org.testng.annotations.AfterSuite;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Unit tests for shared implementation in abstract {@link org.openremote.security.KeyManager}
 * class.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class KeyManagerTest
{
  // TODO : test loading zero file behavior
  // TODO : test saving with non-ascii password


  // Test Lifecycle methods -----------------------------------------------------------------------

  @AfterSuite public void clearSecurityProvider()
  {
    Provider p = Security.getProvider("BC");

    if (p != null)
    {
      Assert.fail("Tests did not properly remove BouncyCastle provider.");
    }
  }


  /**
   * Very basic test runs on StorageType enum to ensure implementation consistency.
   */
  @Test public void testStorageTypes()
  {
    Assert.assertTrue(
        KeyManager.Storage.PKCS12.name().equals(KeyManager.Storage.PKCS12.toString())
    );

    Assert.assertTrue(
        KeyManager.Storage.PKCS12.name().equals(KeyManager.Storage.PKCS12.getStorageName())
    );

    Assert.assertTrue(
        KeyManager.Storage.JCEKS.name().equals(KeyManager.Storage.JCEKS.toString())
    );

    Assert.assertTrue(
        KeyManager.Storage.JCEKS.name().equals(KeyManager.Storage.JCEKS.getStorageName())
    );


    Assert.assertTrue(
        KeyManager.Storage.BKS.name().equals(KeyManager.Storage.BKS.toString())
    );

    Assert.assertTrue(
        KeyManager.Storage.BKS.name().equals(KeyManager.Storage.BKS.getStorageName())
    );
  }


  // Save tests -----------------------------------------------------------------------------------

  /**
   * Tests keystore save when file descriptor is null.
   *
   * @throws Exception  if test fails
   */
  @Test public void testSaveWithNullFile() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();

    char[] storePW = new char[] { 'f', 'o', 'o'};

    try
    {
      keyMgr.save(null, storePW);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  /**
   * Tests storing an empty in-memory keystore.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testEmptyInMemoryKeystore() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();
    char[] password = new char[] { 'f', 'o', 'o' };

    KeyStore keystore = keyMgr.save(password);

    Assert.assertTrue(keystore.size() == 0);

    // Ensure we've erased the password from memory after API call...

    for (char c : password)
    {
      Assert.assertTrue(c == 0);
    }
  }


  /**
   * Tests storing an empty in-memory keystore with empty keystore password.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testEmptyInMemoryKeystoreWithEmptyPassword() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();

    try
    {
      keyMgr.save(new char[] { });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests storing an empty in-memory keystore with null keystore password.
   *
   * @throws Exception  if test fails for any reason
   */
  @Test public void testEmptyInMemoryKeystoreWithNullPassword() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();

    try
    {
      keyMgr.save(null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests storing a keystore with null master password.
   *
   * @throws Exception  if test fails
   */
  @Test public void testFileKeyStoreNullPassword() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    try
    {
      keyMgr.save(f.toURI(), null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected
    }
  }


  /**
   * Test behavior when loading keystore with wrong password.
   *
   * @throws Exception  if test fails
   */
  @Test public void testWrongPassword() throws Exception
  {
    JCEKSStorage ks = new JCEKSStorage();

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    ks.add(
        "alias",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    char[] password = new char[] { 'f', 'o', 'o' };

    ks.save(f.toURI(), password);

    try
    {
      ks.save(f.toURI(), new char[] { 0 });

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Test behavior when a secret key is added to storage that does not
   * support them.
   *
   * @throws Exception  if test fails
   */
  @Test public void testAddingSecretKeyToPKCS12() throws Exception
  {
    PKCS12Storage ks = new PKCS12Storage();

    ks.add(
        "alias",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    char[] password = new char[] { 'f', 'o', 'o' };

    try
    {
      ks.save(password);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Tests adding a secret key to JCEKS storage.
   *
   * @throws Exception  if test fails
   */
  @Test public void testAddingSecretKeyToJCEKS() throws Exception
  {
    JCEKSStorage ks = new JCEKSStorage();

    ks.add(
        "alias",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    char[] password = new char[] { 'f', 'o', 'o' };

    ks.save(password);
  }

  /**
   * Tests adding a secret key to BouncyCastle UBER storage.
   *
   * @throws Exception  if test fails
   */
  @Test public void testAddingSecretKeyToUBER() throws Exception
  {
    // UBER implementation requires "BC" to be available as security provider...

    try
    {
      Security.addProvider(new BouncyCastleProvider());

      UBERStorage ks = new UBERStorage();

      ks.add(
          "alias",
          new KeyStore.SecretKeyEntry(
              new SecretKeySpec(new byte[] { 'a' }, "test")
          ),
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      char[] password = new char[] { 'f', 'o', 'o' };

      KeyStore keystore = ks.save(password);

      Assert.assertTrue(keystore.getType().equals("UBER"), "got " + keystore.getType());
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  /**
   * Test implementation behavior when requested keystore algorithm is not available.
   *
   * @throws Exception  if test fails
   */
  @Test public void testAddingSecretKeyToUnavailableBKS() throws Exception
  {
    UnavailableBKS ks = new UnavailableBKS();

    ks.add(
        "alias",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    char[] password = new char[] { 'f', 'o', 'o' };

    try
    {
      ks.save(password);

      Assert.fail("Should not get here...");
    }

    catch (KeyManager.ConfigurationException e)
    {
      // expected...
    }
  }


  /**
   * Tests behavior when an existing keystore has been corrupted.
   *
   * @throws Exception  if test fails
   */
  @Test public void testCorruptJCEKS() throws Exception
  {
    JCEKSStorage ks = new JCEKSStorage();

    ks.add(
        "alias",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    char[] password = new char[] { 'f', 'o', 'o' };
    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    ks.add(
        "foobar",
        new KeyStore.SecretKeyEntry(
            new SecretKeySpec(new byte[] { 'a' }, "test")
        ),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    ks.save(f.toURI(), password);

    FileOutputStream fout = new FileOutputStream(f);
    BufferedOutputStream bout = new BufferedOutputStream(fout);

    bout.write("Add some garbage".getBytes());
    bout.close();

    password = new char[] { 'f', 'o', 'o' };

    try
    {
      ks.save(f.toURI(), password);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  /**
   * Tests storing a keystore with empty master password.
   *
   * @throws Exception  if test fails
   */
  @Test public void testFileKeyStoreEmptyPassword() throws Exception
  {
    TestKeyManager keyMgr = new TestKeyManager();

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    try
    {
      keyMgr.save(f.toURI(), new char[] {});

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * Test against a broken implementation (subclass) of a key manager.
   */
  @Test public void testBrokenStorageManager()
  {
    try
    {
      new BrokenStorageManager();

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Test error behavior when file doesn't exist.
   */
  @Test public void testSaveWithBrokenFile()
  {
    TestKeyManager mgr = new TestKeyManager();

    File f = new File("///");
    char[] pw = new char[] { 'p' };

    try
    {
      mgr.save(f.toURI(), pw);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }

    for (Character c : pw)
    {
      Assert.assertTrue(c == 0);
    }
  }

  /**
   * Tests error handling behavior on add() with null alias.
   *
   * @see KeyManager#add(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)
   */
  @Test public void testAddNullAlias()
  {
    TestKeyManager mgr = new TestKeyManager();

    try
    {
      mgr.add(
          null,
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { 'a' }, "foo")),
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Tests error handling behavior on add() with empty alias.
   *
   * @see KeyManager#add(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)
   */
  @Test public void testAddEmptyAlias()
  {
    TestKeyManager mgr = new TestKeyManager();

    try
    {
      mgr.add(
          "",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { 'a' }, "foo")),
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  /**
   * Tests error handling behavior on add() with empty alias.
   *
   * @see KeyManager#add(String, java.security.KeyStore.Entry, java.security.KeyStore.ProtectionParameter)
   */
  @Test public void testAddNullEntry()
  {
    TestKeyManager mgr = new TestKeyManager();

    try
    {
      mgr.add(
          "test",
          null,
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      Assert.fail("should not get here...");
    }

    catch (IllegalArgumentException e)
    {
      // expected...
    }
  }

  // InstantiateKeyStore Tests --------------------------------------------------------------------

  /**
   * Basic test to invoke createKeyStore()
   *
   * @throws Exception    if test fails
   */
  @Test public void testCreateKeyStore() throws Exception
  {
    TestKeyManager mgr = new TestKeyManager();
    KeyStore store = mgr.createKeyStore();

    Assert.assertTrue(store != null);
  }


  // Load Tests -----------------------------------------------------------------------------------

  /**
   * Tests saving and loading secret keys with BouncyCastle UBER storage.
   *
   * @throws Exception    if test fails
   */
  @Test public void testLoadExistingKeyStoreUBER() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      UBERStorage mgr = new UBERStorage();

      mgr.add(
          "test",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { 'a' }, "foo")),
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      File dir = new File(System.getProperty("user.dir"));
      File f = new File(dir, "test.keystore." + UUID.randomUUID());
      f.deleteOnExit();

      char[] pw = new char[] { '1' };

      mgr.save(f.toURI(), pw);

      pw = new char[] { '1' };

      KeyStore ks = mgr.load(f.toURI(), pw);

      KeyStore.SecretKeyEntry entry =
          (KeyStore.SecretKeyEntry)ks.getEntry("test", new KeyStore.PasswordProtection(new char[] {'b'}));

      Assert.assertTrue(Arrays.equals(entry.getSecretKey().getEncoded(), new byte[] { 'a' }));
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Tests saving and loading secret keys with Sun proprietary JCEKS storage.
   *
   * @throws Exception    if test fails
   */
  @Test public void testLoadExistingKeyStoreJCEKS() throws Exception
  {
    JCEKSStorage mgr = new JCEKSStorage();

    mgr.add(
        "test",
        new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { 'a' }, "foo")),
        new KeyStore.PasswordProtection(new char[] { 'b' })
    );

    File dir = new File(System.getProperty("user.dir"));
    File f = new File(dir, "test.keystore." + UUID.randomUUID());
    f.deleteOnExit();

    char[] pw = new char[] { '1' };

    mgr.save(f.toURI(), pw);

    pw = new char[] { '1' };

    KeyStore ks = mgr.load(f.toURI(), pw);

    KeyStore.SecretKeyEntry entry =
        (KeyStore.SecretKeyEntry)ks.getEntry("test", new KeyStore.PasswordProtection(new char[] {'b'}));

    Assert.assertTrue(Arrays.equals(entry.getSecretKey().getEncoded(), new byte[] { 'a' }));
  }

  /**
   * Tests error behavior when null file descriptor is used.
   *
   * @throws Exception    if test fails
   */
  @Test public void testLoadingNullFile() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      UBERStorage mgr = new UBERStorage();

      mgr.add(
          "test",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] {'a'}, "foo")),
          new KeyStore.PasswordProtection(new char[] {'b'})
      );

      char[] pw = new char[] { '1' };

      try
      {
        mgr.load(null, pw);

        Assert.fail("should not get here...");
      }

      catch (KeyManager.KeyManagerException e)
      {
        // expected...
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }

  /**
   * Tests the error handling behavior when null password is given.
   *
   * @throws Exception    if test fails
   */
  @Test public void testLoadingWithNullPassword() throws Exception
  {
    try
    {
      Security.addProvider(SecurityProvider.BC.getProviderInstance());

      UBERStorage mgr = new UBERStorage();

      mgr.add(
          "test",
          new KeyStore.SecretKeyEntry(new SecretKeySpec(new byte[] { 'a' }, "foo")),
          new KeyStore.PasswordProtection(new char[] { 'b' })
      );

      File dir = new File(System.getProperty("user.dir"));
      File f = new File(dir, "test.keystore." + UUID.randomUUID());
      f.deleteOnExit();

      try
      {
        mgr.load(f.toURI(), null);

        Assert.fail("should not get here...");
      }

      catch (KeyManager.KeyManagerException e)
      {
        // expected...
      }
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }


  // Nested Classes -------------------------------------------------------------------------------

  private static class TestKeyManager extends KeyManager
  {
    // no op, just to test abstract superclass implementation...
  }

  /**
   * KeyManager for Sun JCEKS keystorage. This implementation searches for a correct provider
   * that implements the Sun proprietary JCEKS storage, or asserts a failure of no security
   * provider is found to execute the test.
   */
  private static class JCEKSStorage extends KeyManager
  {
    private static Provider findJCEKSProvider()
    {
      Map<String, String> props = new HashMap<String, String>();
      props.put("keystore.jceks", "");
      Provider[] providers = Security.getProviders(props);

      if (providers.length == 0)
      {
        Assert.fail("Cannot find a security provider for Sun JCEKS");

        return null;
      }

      else
      {
        return providers[0];
      }
    }

    JCEKSStorage()
    {
      super(StorageType.JCEKS, findJCEKSProvider());
    }
  }

  /**
   * UBER keystorage from BouncyCastle.
   */
  private static class UBERStorage extends KeyManager
  {
    UBERStorage()
    {
      super(StorageType.UBER, new BouncyCastleProvider());
    }
  }

  /**
   * Test KeyManager implementation that attempts to load/create a keystore of a type
   * that is not available in the security provider.
   */
  private static class UnavailableBKS extends KeyManager
  {
    UnavailableBKS()
    {
      super(StorageType.BKS, new EmptyProvider());
    }
  }

  /**
   * PKCS12 storage from a default security prover.
   */
  private static class PKCS12Storage extends KeyManager
  {
    PKCS12Storage()
    {
      super(StorageType.PKCS12, null);
    }
  }

  private static class BrokenStorageManager extends KeyManager
  {
    BrokenStorageManager()
    {
      super(null, new BouncyCastleProvider());
    }
  }

  /**
   * An empty test security provider used for some test cases.
   */
  private static class EmptyProvider extends Provider
  {
    EmptyProvider()
    {
      super("Empty Test Provider", 0.0, "Testing");
    }
  }
}

