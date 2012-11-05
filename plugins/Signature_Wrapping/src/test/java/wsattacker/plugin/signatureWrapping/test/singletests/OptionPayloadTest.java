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
package wsattacker.plugin.signatureWrapping.test.singletests;

import static org.junit.Assert.*;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.domToString;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;
import wsattacker.plugin.signatureWrapping.test.util.Signer;
import wsattacker.plugin.signatureWrapping.test.util.SoapTestDocument;

public class OptionPayloadTest
{

  private static Signer s;

  @BeforeClass
  public static void setUpBeforeClass() {
    s = new Signer(null);
  }

  @Test
  public void timestampTestInMilliseconds() throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    soap.setTimestamp(true,true);
    Element t = soap.getTimestamp();
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(t));
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(doc));

    OptionPayload o = new OptionPayload(null, "name", t, "timestampoption");

    assertTrue("Not a Timestamp Element:\n"+ domToString(t), o.isTimestamp());
    Element p = o.getPayloadElement();
    assertTrue("Expired: "+ domToString(p), s.verifyTimestamp(p));
  }

  @Test
  public void timestampTest() throws Exception
  {
    SoapTestDocument soap = new SoapTestDocument();
    Document doc = soap.getDocument();
    soap.setTimestamp(true,false);
    Element t = soap.getTimestamp();
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(t));
    assertFalse("Not Expired:\n"+ domToString(t), s.verifyTimestamp(doc));

    OptionPayload o = new OptionPayload(null, "name", t, "timestampoption");

    assertTrue("Not a Timestamp Element:\n"+ domToString(t), o.isTimestamp());
    Element p = o.getPayloadElement();
    assertTrue("Expired: "+ domToString(p), s.verifyTimestamp(p));
  }

}
