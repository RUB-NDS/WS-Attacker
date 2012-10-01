/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework
 * Copyright (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package wsattacker.plugin.signatureWrapping.xpath.parts.util;

import java.util.List;

import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathPartInterface;

/**
 * Helper Class which provides useful functions to analyse an XPath.
 * 
 * @author christian
 * 
 */
public class XPathInspectorTools
{
  /**
   * Find the next character 'needle' in the String 's' beginning at 'startIndex'. Needles in parts surrounded with
   * quotes (like attribute values) are ignored.
   * 
   * @param s
   *          : String to search
   * @param needle
   *          : What to search
   * @param startIndex
   *          : Where to start
   * @return position of next 'needle' > start or -1 if not found
   */
  public static int nextChar(String s,
                             char needle,
                             int startIndex)
  {
    boolean inSingleQuote = false;
    boolean inDoubleQuote = false;
    for (int i = startIndex; i < s.length(); ++i)
    {
      char c = s.charAt(i);
      if (!inSingleQuote && !inDoubleQuote && c == needle) {
					return i;
			}
      if (!inSingleQuote && c == '"') {
					inDoubleQuote ^= true;
			}
      else if (!inDoubleQuote && c == '\'') {
					inSingleQuote ^= true;
			}
    }
    return -1; // no more needles
  }

  /**
   * Analog to 'nextChar()' but searches for a String 'needle'
   * 
   * @param s
   *          : String to search
   * @param needle
   *          : What to search
   * @param startIndex
   *          : Where to start
   * @return position of next 'needle' > start or -1 if not found
   */
  public static int nextString(String s,
                               String needle,
                               int startIndex)
  {
    int next;
    char[] n = needle.toCharArray();
    mainloop:
    do
    {
      next = nextChar(s, n[0], startIndex);
      for (int i = 1; i < n.length; i++)
      {
        if (nextChar(s, n[i], next + i) != (next + i))
        {
          startIndex = next + i;
          continue mainloop;
        }
      }
      return next;
    }
    while (next >= 0);
    return next;
  }

  /**
   * Implodes a List with ", " to get a String representation. The toFullString() Method is called on each XPathPart.
   * 
   * @param list
   * @return
   */
  public static String implodeList(List<? extends XPathPartInterface> list)
  {
    return implodeList(list, "", "", "");
  }

  public static String implodeList(List<? extends XPathPartInterface> list,
                                   String implode)
  {
    return implodeList(list, implode, "", "");
  }

  public static String implodeList(List<? extends XPathPartInterface> list,
                                   String implode,
                                   String before,
                                   String after)
  {
    StringBuilder buf = new StringBuilder();
    if (list.size() > 0) {
				  buf.append(before).append(list.get(0).toFullString()).append(after);
		  }
    for (int i = 1; i < list.size(); ++i) {
				  buf.append("/").append(before).append(list.get(i).toFullString()).append(after);
		  }
    return buf.toString();
  }
}
