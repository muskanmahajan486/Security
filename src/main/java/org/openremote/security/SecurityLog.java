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

import org.openremote.logging.Hierarchy;

/**
 * Log categories used in this OpenRemote security package. This enum should include all the
 * categories this package uses for logging, making it easier for tooling to expose available
 * and used log categories to end-users. <p>
 *
 * Rather than a typical developer-oriented log category based on package names, the log
 * hierarchy names here should be defined as logical units that are conceptually easy to
 * understand by operational users who are not familiar with how the source code has been
 * structured. Security related logs cross-cut across an application and therefore do not
 * logically belong solely to any one source code package. The log categories here may be
 * used by other packages and classes as well. <p>
 *
 * @author <a href="mailto:juha@openremote.org">Juha Lindfors</a>
 */
public enum SecurityLog implements Hierarchy
{
  DEFAULT;

  @Override public String getCanonicalLogHierarchyName()
  {
    // So far we just have one category so return the same canonical name always...

    return "Security";
  }

}
