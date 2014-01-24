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
import org.testng.annotations.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.UUID;

/**
 * Unit tests for {@link org.openremote.security.PasswordManager}
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class PasswordManagerTest
{

  // Test No-Arg Constructor ----------------------------------------------------------------------

  /**
   * No arg constructor test with basic parameters.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtor() throws Exception
  {
    char[] pw = new char[] { 'a', '1' };

    PasswordManager mgr = new PasswordManager(pw);

    // check that password was erased....

    for (Character c : pw)
    {
      Assert.assertTrue(c == 0);
    }
  }

  /**
   * No arg constructor test with null password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtorNullPassword() throws Exception
  {
    try
    {
      new PasswordManager(null);
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }

  /**
   * No arg constructor test with empty password.
   *
   * @throws Exception    if test fails
   */
  @Test public void testNoArgCtorEmptyPassword() throws Exception
  {
    try
    {
      new PasswordManager(new char[] {} );
    }

    catch (KeyManager.KeyManagerException e)
    {
      // expected...
    }
  }



  @Test public void testAddAndRemovePassword() throws Exception
  {
    try
    {
      Security.addProvider(new BouncyCastleProvider());

      File dir = new File(System.getProperty("user.dir"));
      File file = new File(dir, "password-store-" + UUID.randomUUID());
      file.deleteOnExit();
      URI uri = file.toURI();

      char[] masterPassword = new char[] { '1', '2', '3' };

      PasswordManager mgr = new PasswordManager(uri, masterPassword);

      byte[] password = new byte[] { 'a', 'b', 'c', 'd' };
      masterPassword = new char[] { '1', '2', '3' };

      mgr.addPassword("mypassword", password, masterPassword);

      KeyStore ks = KeyStore.getInstance(KeyManager.StorageType.BKS.getStorageTypeName(), new BouncyCastleProvider());

      masterPassword = new char[] { '1', '2', '3' };
      ks.load(new FileInputStream(new File(uri)), masterPassword);

      Assert.assertTrue(ks.containsAlias("mypassword"));
      Assert.assertTrue(ks.size() == 1);

      masterPassword = new char[] { '1', '2', '3' };
      KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry)ks.getEntry(
          "mypassword", new KeyStore.PasswordProtection(masterPassword)
      );

      SecretKey secret = entry.getSecretKey();
      byte[] loadedPassword = secret.getEncoded();
      byte[] originalPassword = new byte[] { 'a', 'b', 'c', 'd' };

      Assert.assertTrue(Arrays.equals(loadedPassword, originalPassword));

      masterPassword = new char[] { '1', '2', '3' };
      mgr.removePassword("mypassword", masterPassword);

      ks = KeyStore.getInstance(KeyManager.StorageType.BKS.getStorageTypeName(), new BouncyCastleProvider());

      masterPassword = new char[] { '1', '2', '3' };
      ks.load(new FileInputStream(new File(uri)), masterPassword);

      Assert.assertTrue(ks.size() == 0);
    }

    finally
    {
      Security.removeProvider("BC");
    }
  }
}

