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

import org.openremote.logging.Logger;

import java.security.Provider;
import java.security.Security;

/**
 * Provides some generic methods to work on JVM installed security providers.
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public class Providers
{

  private final static Logger log = Logger.getInstance(SecurityLog.CONFIGURATION);

  public static void main(String... args)
  {
    Provider[] providers = Security.getProviders();
    StringBuilder builder = new StringBuilder(1024);

    for (Provider provider : providers)
    {
      builder.append("\nPROVIDER:");
      builder.append(provider.getName());
      builder.append("\n            ");
      builder.append(provider.getInfo());
      builder.append("\n");
    }

    log.error(builder.toString());
  }
}

