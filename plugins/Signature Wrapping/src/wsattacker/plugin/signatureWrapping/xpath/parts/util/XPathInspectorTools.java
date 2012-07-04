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
      if (!inSingleQuote && !inDoubleQuote && c == needle)
        // Found needle, which is not in a quote
        return i;
      if (!inSingleQuote && c == '"')
        // Not in SingleQoute but found DoubleQuote -> Toggle inDoubleQuote
        inDoubleQuote ^= true;
      else if (!inDoubleQuote && c == '\'')
        // Not in DoubleQuote but found SingleQuote -> Toggle inSingleQuote
        inSingleQuote ^= true;
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
    StringBuffer buf = new StringBuffer();
    if (list.size() > 0)
      buf.append(before).append(list.get(0).toFullString()).append(after);
    for (int i = 1; i < list.size(); ++i)
      buf.append("/").append(before).append(list.get(i).toFullString()).append(after);
    return buf.toString();
  }
}
