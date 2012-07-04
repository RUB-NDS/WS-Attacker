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
