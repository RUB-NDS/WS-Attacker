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
package wsattacker.plugin.signatureWrapping.test.util;

import com.sun.org.apache.xml.internal.security.signature.XMLSignatureInput;
import java.util.List;
import javax.xml.crypto.Data;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMURIReference;
import org.apache.log4j.Logger;
import org.jcp.xml.dsig.internal.dom.ApacheNodeSetData;
import org.jcp.xml.dsig.internal.dom.ApacheOctetStreamData;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import wsattacker.plugin.signatureWrapping.util.dom.DomUtilities;

public class WsuURIDereferencer implements URIDereferencer
{

  private static Logger log = Logger.getLogger(WsuURIDereferencer.class);

  @Override
  public Data dereference(URIReference uriReference,
                          XMLCryptoContext context)
                                                   throws URIReferenceException
  {

    if (uriReference == null) {
		  throw new NullPointerException("URI can not be null");
	  }

    DOMURIReference domRef = (DOMURIReference) uriReference;
    Document doc = domRef.getHere().getOwnerDocument();
//    Attr uriAttr = (Attr) domRef.getHere();
    String uri = uriReference.getURI();

    Element referencedElement = null;

    if (uri.isEmpty()) {
		  referencedElement = doc.getDocumentElement();
	  }

    if (uri != null && uri.length() != 0 && uri.charAt(0) == '#')
    {
      String id = uri.substring(1);
      List<Element> referenced = DomUtilities.findElementByWsuId(doc, id);
      if (referenced.isEmpty())
      {
        log.warn("No Data to dereference found. Returning NULL");
        return null;
      }
      if (referenced.size() > 1) {
		    log.warn("Multiple matches for Wsu:Id " + id + " / Found " + referenced.size() + " Elements! --> Use the first!");
	    }
      referencedElement = referenced.get(0);
      log.debug("wsu:Id='" + id + "' is resolved to : " + DomUtilities.getFastXPath(referencedElement));
    }

    if (referencedElement != null)
    {
      XMLSignatureInput in = new XMLSignatureInput(referencedElement);
      if (in.isOctetStream())
      {
        try
        {
          log.debug("Returning ApacheOctetStreamData");
          return new ApacheOctetStreamData(in);
        }
        catch (Exception e)
        {
          e.printStackTrace();
          return null;
        }
      }
      else
      {
        log.debug("Returning ApacheNodeSetData");
        return new ApacheNodeSetData(in);
      }
    }
    log.warn("Returned null --> this code line should never be used!");
    return null;
  }
}
