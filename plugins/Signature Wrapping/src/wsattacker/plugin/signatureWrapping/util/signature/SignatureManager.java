package wsattacker.plugin.signatureWrapping.util.signature;

import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.findChildren;
import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.getFirstChildElement;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSSE_1_0;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.URI_NS_WSSE_1_1;

import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.XMLSignature;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.option.OptionPayload;

/**
 * This class defines which parts of an XML Document is signed. For this concrete use-case, it searches for a
 * WS-Security Header element which contains a Signature child. The Reference elements are then accessable.
 */
public class SignatureManager
{

  private Document         doc;
  private SignatureElement sig;

  public SignatureManager()
  {
  }

  /**
   * Sets the current working Document.
   * 
   * @param doc
   */
  public void setDocument(Document doc)
  {
    this.doc = doc;
    eval();
  }

  /**
   * Gets the current working Document.
   * 
   * @return
   */
  public Document getDocument()
  {
    return doc;
  }

  /**
   * Returns the Signature Element Node
   * 
   * @return
   */
  public SignatureElement getSignatureElement()
  {
    return sig;
  }

  private Logger log()
  {
    return Logger.getLogger(getClass());
  }

  /**
   * Processes the Document - Searches for References - Searches for XPath Expressions
   * 
   * @return
   */
  private synchronized void eval()
  {
    if (doc == null)
    {
      sig = null;
      return; // nothing to do
    }
    // log().debug("Verifying Document:\n" +
    // SoapUtilities.domToString(doc));
    // Element sigElement =
    // getFirstChildElement(getFirstChildElement(getFirstChildElement(doc.getDocumentElement())));
    Element envelope = doc.getDocumentElement();
    // Element envelope = getFirstChildElement(doc);
    Element header = getFirstChildElement(envelope);

    List<Element> securityList = findChildren(header, "Security", URI_NS_WSSE_1_0);
    if (securityList.size() != 1)
    {
      securityList = findChildren(header, "Security", URI_NS_WSSE_1_1);
      if (securityList.size() != 1)
      {
        log().warn("Could not find WS Security Header");
        return;
      }
    }
    Element security = securityList.get(0);

    List<Element> signatureList = findChildren(security, "Signature", XMLSignature.XMLNS);
    if (signatureList.size() != 1)
    {
      log().warn("There are " + signatureList.size() + " Signature Elements");
      return;
    }
    Element signature = signatureList.get(0);

    log().trace("Found Signature Element " + signature.getNodeName());
    sig = new SignatureElement(signature);
  }

  /**
   * Get a List of all PayloadOptions. Each PayloadOption referres to the original Signed Content and additional
   * contains the Payload to use for the attack.
   * 
   * @return List of all PayloadOptions
   */
  public List<OptionPayload> getPayloads()
  {
    List<OptionPayload> payloads = new ArrayList<OptionPayload>();
    if (getSignatureElement() != null)
    {
      for (ReferenceElement ref : getSignatureElement().getReferences())
      {
        if (ref.getPayload() != null)
          payloads.add(ref.getPayload());
        else
        {
          for (XPathElement xpath : ref.getXPaths())
            for (OptionPayload option : xpath.getPayloads())
              payloads.add(option);
        }
      }
    }
    return payloads;
  }
}
