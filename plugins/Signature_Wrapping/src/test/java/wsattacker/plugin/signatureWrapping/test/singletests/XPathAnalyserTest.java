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

import java.util.ArrayList;
import java.util.List;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import wsattacker.plugin.signatureWrapping.xpath.analysis.XPathAnalyser;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeaknessInterface;
import wsattacker.plugin.signatureWrapping.xpath.interfaces.XPathWeaknessFactoryInterface;
import wsattacker.plugin.signatureWrapping.xpath.parts.AbsoluteLocationPath;

import org.w3c.dom.*;

import wsattacker.plugin.signatureWrapping.schema.SchemaAnalyzerInterface;

public class XPathAnalyserTest
{
  private static XPathWeaknessFactoryInterface save;

  @BeforeClass
  public static void setUpBeforeClass()
  {
    save = XPathAnalyser.xpathWeaknessFactory;
    XPathAnalyser.xpathWeaknessFactory = new XPathWeaknessFactoryInterface()
    {

      @Override
      public List<XPathWeaknessInterface> generate(AbsoluteLocationPath xpath,
                                          Element signedElement,
                                          Element payloadElement,
                                          SchemaAnalyzerInterface schemaAnalyser)
      {
        return new ArrayList<XPathWeaknessInterface>();
      }
    };
  }

  @AfterClass
  public static void setUpAfterClass()
  {
    XPathAnalyser.xpathWeaknessFactory = save;
  }

  @Test
  public void fastXPathTest()
  {
    XPathAnalyser a;
    String xpath;

    // True
    xpath = "/Envelope[1]/Body[1]/function[1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

    xpath = "/Envelope[1]/Header[1]/Security[1][@role=\"next\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

    // False
    xpath = "//Body[1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    xpath = "/Envelope[1]/Body/Function";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    xpath = "/Envelope[1]/Header[1]/Security[1][@role=\"next\" or @mustUnderstand=\"true\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    // Slash in attribut value
    xpath = "/Envelope[@attr='/etc/passwd']";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

    xpath = "/Envelope[@attr=\"/etc/passwd\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

    xpath = "/Envelope[@attr='/etc/passwd']/Body[@attr=\"/etc/shadow\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

    xpath = "/Envelope[1 and 0]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    xpath = "/Envelope[1[2]3]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    // two many expressions
    xpath = "/Envelope[1][2][3]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    xpath = "/Envelope[1][2]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    xpath = "/Envelope[@foo='1'][@bar='2']";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isFastXPath());

    // "real" case
    xpath = "/soapenv:Envelope[1]/soapenv:Body[1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isFastXPath());

  }


  @Test
  public void prefixFreeFastXPathTest()
  {
    XPathAnalyser a;
    String xpath;

    // True
    xpath = "/*[local-name()='e' and namespace-uri()='ns_e'][1]/*[local-name()=\"h\" and namespace-uri()=\"ns_h\"][@id='bla']";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isPrefixfreeTransformedFastXPath());

    // True / order independent

    xpath = "/*[1][local-name()='e' and namespace-uri()='ns_e']/*[@id='bla'][local-name()=\"h\" and namespace-uri()=\"ns_h\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isPrefixfreeTransformedFastXPath());

    // False with double slash
    xpath = "/*[local-name()='e' and namespace-uri()='ns_e'][1]//*[local-name()=\"h\" and namespace-uri()=\"ns_h\"][@id='bla']";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isPrefixfreeTransformedFastXPath());

    // No Position Inde
    xpath = "/*[local-name()='e' and namespace-uri()='ns_e']/*[local-name()=\"h\" and namespace-uri()=\"ns_h\"][@id='bla']";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isPrefixfreeTransformedFastXPath());

    // No Attribute
    xpath = "/*[local-name()='e' and namespace-uri()='ns_e'][1]/*[local-name()=\"h\" and namespace-uri()=\"ns_h\"]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isPrefixfreeTransformedFastXPath());

    // FastXPath
    xpath = "/Envelope[1]/Body[1]/function[1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertFalse(a.isPrefixfreeTransformedFastXPath());
  }

  @Test
  public void xspresXPaths()
  {
    XPathAnalyser a;
    String xpath;

    xpath = "/*[local-name()=\"Envelope\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Body\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isPrefixfreeTransformedFastXPath());

    xpath = "/*[local-name()=\"Envelope\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Header\" and namespace-uri()=\"http://schemas.xmlsoap.org/soap/envelope/\"][1]/*[local-name()=\"Security\" and namespace-uri()=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"][1]/*[local-name()=\"Timestamp\" and namespace-uri()=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"][1]";
    a = new XPathAnalyser(xpath, null, null, null);
    assertTrue(a.isPrefixfreeTransformedFastXPath());
  }
}
