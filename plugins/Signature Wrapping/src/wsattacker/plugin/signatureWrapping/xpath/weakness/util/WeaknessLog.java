package wsattacker.plugin.signatureWrapping.xpath.weakness.util;

import java.util.ArrayList;
import java.util.List;

import com.eviware.soapui.support.StringUtils;

/**
 * Simple logging class.
 * Each XPathWeakness can append a simple String to the log.
 */
public class WeaknessLog
{
  
  private static List<String> log = new ArrayList<String>();
  
  /**
   * Cleans all saved log entries.
   */
  public static void clean() {
    log.clear();
  }
  
  /**
   * Append a simple string.
   * @param message
   */
  public static void append(String message) {
    log.add(message);
  }
  
  /**
   * Returns the entries as a List.
   * @return List of Logentries.
   */
  public static List<String> get() {
    return log;
  }
  
  /**
   * Returns the list as a String representation.
   * @return Logstring.
   */
  public static String representation() {
    String [] ret = {};
    return StringUtils.join(log.toArray(ret), "\n");
  }

}
