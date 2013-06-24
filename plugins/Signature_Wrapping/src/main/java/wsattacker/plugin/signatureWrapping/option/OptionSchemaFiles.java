/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
package wsattacker.plugin.signatureWrapping.option;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import wsattacker.gui.composition.AbstractOptionGUI;
import wsattacker.main.composition.ControllerInterface;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.option.AbstractOptionComplex;

/**
 * Simple multifile select option.
 * Used to selecte multiple XML Schema files.
 */
public class OptionSchemaFiles extends AbstractOptionComplex
{

  private static final long serialVersionUID = 1L;
  List<File> files = new ArrayList<File>();

  public OptionSchemaFiles()
  {
    super("Used\nSchema\nfiles", "Set the Schema Files.\nSoap11, Soap12, WSA, WSSE, WSU, DS and XPathFilter2\nare included by default.");
  }

  public void setFiles(List<File> files)
  {
    this.files = files;
  }

  public void setFiles(File[] files)
  {
    this.files = new ArrayList<File>(files.length);
    for (File f : files)
    {
      this.files.add(f);
      Logger.getLogger(getClass()).info("Using Schema: " + f.toString());
    }
  }

  public List<File> getFiles()
  {
    return files;
  }

  @Override
  public AbstractOptionGUI getComplexGUI(ControllerInterface controller,
                                         AbstractPlugin plugin)
  {
    return new OptionSchemaFilesGUI(controller, plugin, this);
  }

  public boolean isValid(File file)
  {
    return file == null || file.exists() && file.isFile();
  }

  public boolean isValid(File[] files)
  {
    boolean valid = true;
    for (File f : files) {
		  if (!isValid(f)) {
		    valid = false;
		    break;
	    }
	  }
    return valid;
  }

  @Override
  public boolean isValid(String value)
  {
    boolean valid = true;
    String[] values = value.split(", ");
    for (String name : values)
      try
      {
        new File(name);
      }
      catch (Exception e)
      {
        valid = false;
      }
    return valid;
  }

  @Override
  public boolean parseValue(String value)
  {
    boolean valid = true;
    String[] values = value.split(", ");
    files = new ArrayList<File>();
    for (String name : values)
      try
      {
        files.add(new File(name));
      }
      catch (Exception e)
      {
        files.clear();
        valid = false;
      }
    return valid;
  }

  @Override
  public String getValueAsString()
  {
    StringBuilder buf = new StringBuilder();
    for (File f : files) {
		  buf.append(f.toString()).append(", ");
	  }
    if (buf.length() > 2) {
		  buf.delete(buf.length() - 2, buf.length());
	  }
    return buf.toString();
  }

  public String getShortValueAsString()
  {
    StringBuilder buf = new StringBuilder();
    for (File f : files) {
		  buf.append(f.getName()).append(", ");
	  }
    if (buf.length() > 2) {
		  buf.delete(buf.length() - 2, buf.length());
	  }
    return buf.toString();
  }

}
