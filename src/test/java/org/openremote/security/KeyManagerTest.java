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

import java.io.File;
import java.security.KeyStore;
import java.util.UUID;

/**
 * Unit tests for shared implementation in abstract {@link org.openremote.security.KeyManager}
 * class.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class KeyManagerTest
{
  /**
   * Very basic test runs on StorageType enum to ensure implementation consistency.
   */
  @Test public void testStorageTypes()
  {
    Assert.assertTrue(
        KeyManager.StorageType.PKCS12.name().equals(KeyManager.StorageType.PKCS12.toString())
    );

    Assert.assertTrue(
        KeyManager.StorageType.JCEKS.name().equals(KeyManager.StorageType.JCEKS.toString())
    );

    Assert.assertTrue(
        KeyManager.StorageType.JKS.name().equals(KeyManager.StorageType.JKS.toString())
    );
  }

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
      keyMgr.save(f, null);

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected
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
      keyMgr.save(f, new char[] {});

      Assert.fail("should not get here...");
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }


  // Nested Classes -------------------------------------------------------------------------------

  private static class TestKeyManager extends KeyManager
  {
    // no op, just to test abstract superclass implementation...
  }


}

