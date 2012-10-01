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
package wsattacker.plugin.signatureWrapping.util.signature;

import java.util.*;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class SignatureElement
{

  private Element                signature;
  private List<ReferenceElement> references;

  public SignatureElement(Element signature)
  {
    this.signature = signature;

    List<Element> signedInfo = DomUtilities.findChildren(signature, "SignedInfo", XMLSignature.XMLNS);

    if (signedInfo.size() == 1)
    {

      log().trace("Searching for Reference Elements");
      List<Element> list = DomUtilities.findChildren(signedInfo.get(0), "Reference", XMLSignature.XMLNS);
      references = new ArrayList<ReferenceElement>();
      for (Element ele : list)
        references.add(new ReferenceElement(ele));
      log().trace("Found: " + references);
    }
  }

  public Element getSignature()
  {
    return signature;
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }

  public List<ReferenceElement> getReferences()
  {
    return references;
  }

  @Override
  public boolean equals(Object o)
  {
    if (o instanceof SignatureElement)
    {
      SignatureElement sig = (SignatureElement) o;
      return sig.getReferences().equals(getReferences());
    }
    return false;
  }

}
