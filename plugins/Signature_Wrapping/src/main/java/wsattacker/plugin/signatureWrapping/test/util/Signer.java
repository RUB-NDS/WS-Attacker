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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilter2ParameterSpec;
import javax.xml.crypto.dsig.spec.XPathType;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wsattacker.plugin.signatureWrapping.util.dom.NamespaceResolver;

import static wsattacker.plugin.signatureWrapping.util.dom.DomUtilities.*;
import static wsattacker.plugin.signatureWrapping.util.signature.NamespaceConstants.*;

/**
 * Main Signature Class Is able to sign and verify a Document by XPath and ID
 * 
 */
public class Signer
{

  private static final Logger LOG       = Logger.getLogger(Signer.class);

  private KeyInfoInterface    keyInfo;

  final static String         idString  = "";                            // whole document

  final static int            TIMESTAMP = 60 * 15;                       // 15min
  
//  public static String c14n_method = CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS;
  public static String c14n_method = CanonicalizationMethod.EXCLUSIVE; 

  public String printBytes(byte[] bytes)
  {
    StringBuffer buffer = new StringBuffer();
    for (byte b : bytes)
      buffer.append(String.format("%2X ", b));
    return buffer.toString();
  }

  public Signer(KeyInfoInterface keyInfo)
  {
    this.keyInfo = keyInfo;
  }

  public KeyInfoInterface getKeyInfo()
  {
    return keyInfo;
  }

  public void addTimestamp(Element parent)
  {
    Timestamp timestamp = new Timestamp(false, parent.getOwnerDocument(), TIMESTAMP);
    parent.appendChild(timestamp.getElement());
  }

  // http://www.java2s.com/Code/Java/JDK-6/SignSOAPmessage.htm
  // http://java.sun.com/developer/technicalArticles/xml/dig_signature_api/
  public void sign(Document doc,
                   List<String> whatToSign)
                                           throws Exception
  {

    // Create a DOM XMLSignatureFactory that will be used to
    // generate the enveloped signature.
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance();

    // DigestMethod
    DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA1, null);

    // Instantiate the document to be signed.
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    // Of course, we need namespaces awereness
    dbf.setNamespaceAware(true);

    Element envelope = getFirstChildElement(doc);
    Element header = getFirstChildElement(envelope);
// Element body = getNextSiblingElement(header); // not needed, just
    // nice to know

    // create WS Security Header
    Element wsseHeader;
    List<Element> wsseHeaders = findChildren(header, "Security", URI_NS_WSSE_1_0);
    if (wsseHeaders.isEmpty())
    {
      wsseHeader = doc.createElementNS(URI_NS_WSSE_1_0, PREFIX_NS_WSSE + ":Security");
      header.appendChild(wsseHeader);
    }
    else
    {
      wsseHeader = wsseHeaders.get(0);
    }

    List<String> xpathListToSign = new ArrayList<String>();
    List<String> idListToSign = new ArrayList<String>();

    // seperate ids and xpaths
    for (String r : whatToSign)
    {
      if (r.startsWith("#"))
        idListToSign.add(r);
      else
      {
        // check if xpaths match any elements
        List<Element> match = evaluateXPath(doc, r);
        if (match.size() < 1)
        {
          throw new Exception("Invalid document, can't find node by XPATH:\n\n" + r + "\n\n" + domToString(doc));
        }
        xpathListToSign.add(r);
      }
    }

    if (xpathListToSign.isEmpty() && idListToSign.isEmpty()) {
		  throw new Exception("Nothing to sign specified");
	  }

    // create Reference
    List<Reference> allRefs = new ArrayList<Reference>();
    if (!xpathListToSign.isEmpty())
    {
      List<XPathType> types = new ArrayList<XPathType>(1);

      // Example: How to use XPath
      // types.add(new XPathType(" //ToBeSigned ",
      // XPathType.Filter.INTERSECT));
      // types.add(new XPathType(" //NotToBeSigned ",
      // XPathType.Filter.SUBTRACT));
      // types.add(new XPathType(" //ReallyToBeSigned ",
      // XPathType.Filter.UNION));

      // First XPATH must INTERSECT
      NamespaceResolver res = new NamespaceResolver(doc);
      types.add(new XPathType(xpathListToSign.get(0), XPathType.Filter.INTERSECT, res.getPrefixUriMap()));
      // Other XPaths UNION
      for (int i = 1; i < xpathListToSign.size(); ++i)
        types.add(new XPathType(xpathListToSign.get(i), XPathType.Filter.UNION, res.getPrefixUriMap()));

      XPathFilter2ParameterSpec xp = new XPathFilter2ParameterSpec(types);
      Transform transform = fac.newTransform(Transform.XPATH2, xp);
      List<Transform> transformList = Collections.singletonList(transform);

      Reference ref = fac.newReference(idString, digestMethod, transformList, null, null);
      allRefs.add(ref);
    }

    // Add Ids
    for (String id : idListToSign)
    {
// Reference ref = fac.newReference("first"+id, digestMethod, null, null, "last"+id);
      Reference ref = fac.newReference(id, digestMethod, null, null, null);
      allRefs.add(ref);
    }

    // Create the SignedInfo
    CanonicalizationMethod canonicalizationMethod = fac
        .newCanonicalizationMethod(c14n_method, (C14NMethodParameterSpec) null);
    SignatureMethod signatureMethod = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

    SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, allRefs);

    // Load the KeyStore and get the signing key and certificate.
    KeyStore ks = KeyStore.getInstance("JKS");
    ks.load(new FileInputStream(keyInfo.getKeyStoreFileName()), keyInfo.getKeyStorePassword().toCharArray());
    KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks
        .getEntry(keyInfo.getEntityName(), new KeyStore.PasswordProtection(keyInfo.getEntityPassword().toCharArray()));
    X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

    // Create the KeyInfo containing the X509Data.
    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List<Object> x509Content = new ArrayList<Object>();
    x509Content.add(cert.getSubjectX500Principal().getName());
    x509Content.add(cert);
    X509Data xd = kif.newX509Data(x509Content);
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

    // Append id to first body child (as an example)
    // Element firstBodyChild = getFirstChildElement(body);
    // Attr id = doc.createAttributeNS(uriWSU, prefixWSU+":Id");
    // id.setValue(idString);
    // firstBodyChild.setAttributeNodeNS(id);

    // Create a DOMSignContext and specify the RSA PrivateKey and
    // location of the resulting XMLSignature's parent element.
    DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), wsseHeader);

    // dsc.setDefaultNamespacePrefix("ds");
    dsc.putNamespacePrefix(URI_NS_DS, PREFIX_NS_DS);
    // dsc.setIdAttributeNS(firstBodyChild, uriWSU, "Id");
// dsc.setIdAttributeNS(body, URI_NS_WSU, "Id");
    dsc.setURIDereferencer(new WsuURIDereferencer());

    // Create the XMLSignature, but don't sign it yet.
    XMLSignature xmlSignature = fac.newXMLSignature(si, ki);

    // Marshal, generate, and sign the enveloped signature.
// doc.normalizeDocument();
    xmlSignature.sign(dsc);
// doc.normalizeDocument(); // necessary?

  }

  public boolean verifyTimestamp(Document doc)
                                              throws Exception
  {
    LOG.debug("Verifying Timestamp of Document:\n" + domToString(doc));
    Element envelope = doc.getDocumentElement();

    List<Element> headerList = findChildren(envelope, "Header", envelope.getNamespaceURI());
    if (headerList.size() != 1)
    {
      LOG.warn("Could not find SOAP Header");
      return false;
    }
    Element header = headerList.get(0);

    List<Element> securityList = findChildren(header, "Security", URI_NS_WSSE_1_0);
    if (securityList.size() != 1)
    {
      LOG.warn("Could not find WS Security Header");
      return false;
    }
    Element security = securityList.get(0);

    // Validate Timestamp

    List<Element> timestampList = findChildren(security, "Timestamp", URI_NS_WSU);
    if (timestampList.size() != 1)
    {
      LOG.warn("There are " + timestampList.size() + " Timestamp Elemenets");
      return false;
    }
    
    return verifyTimestamp(timestampList.get(0));
  }
  
  public boolean verifyTimestamp(Element timestampElement)
      throws Exception
{

    Timestamp timestamp = new Timestamp(timestampElement);

    // It would be much easier to use the "isExpired()" Method... but
    // anyhow, it's not available...
    Calendar created = timestamp.getCreated();
    Calendar expires = timestamp.getExpires();
    Calendar now = new GregorianCalendar();
    if (created.after(expires) || expires.before(now))
    {
      LOG.warn("Timestamp is expired");
      return false;
    }
    return true;
}

  // http://download.oracle.com/docs/cd/E17802_01/webservices/webservices/docs/1.6/tutorial/doc/XMLDigitalSignatureAPI8.html
  public boolean verifySignature(Document doc)
                                              throws KeyStoreException,
                                                NoSuchAlgorithmException,
                                                CertificateException,
                                                FileNotFoundException,
                                                IOException,
                                                MarshalException,
                                                XMLSignatureException
  {
// doc.normalize();
// doc.normalizeDocument();
// LOG.debug("Verifying Document:\n" + domToString(doc));
    Element envelope = doc.getDocumentElement();

    List<Element> headerList = findChildren(envelope, "Header", envelope.getNamespaceURI());
    if (headerList.size() != 1)
    {
      LOG.warn("Could not find SOAP Header");
      return false;
    }
    Element header = headerList.get(0);

    List<Element> securityList = findChildren(header, "Security", URI_NS_WSSE_1_0);
    if (securityList.size() != 1)
    {
      LOG.warn("Found " + securityList.size() + " WS Security Headers");
      return false;
    }
    Element security = securityList.get(0);

    List<Element> signatureList = findChildren(security, "Signature", XMLSignature.XMLNS);
    if (signatureList.size() != 1)
    {
      LOG.warn("There are " + signatureList.size() + " Signature Elements");
      return false;
    }
    Element signature = signatureList.get(0);

    // keypair
    DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), signature);
    valContext.setURIDereferencer(new WsuURIDereferencer());

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance();
    XMLSignature xmlSignature = fac.unmarshalXMLSignature(valContext);

    boolean allvalid = xmlSignature.validate(valContext);

    if (!allvalid)
    {

      @SuppressWarnings("unchecked")
      Iterator<Reference> itRef = xmlSignature.getSignedInfo().getReferences().iterator();

      for (int j = 0; itRef.hasNext(); j++)
      { // j is only used if we calculate the Reference Digest, which is out-commmented for performance issues...
        Reference r = itRef.next();

        // These Lines are usefull for debugging, but take performance...
        // **************************************************************
        boolean refValid = r.validate(valContext);
        LOG.debug("ref[" + j + "] validity status: " + refValid);
        LOG.debug(printBytes(r.getCalculatedDigestValue()) + "(Calculated)");
        LOG.debug(printBytes(r.getDigestValue()) + "(Saved value)");
        LOG.debug("Type: " + r.getType() + " / URI: " + r.getURI());
      }

      // These Lines are usefull for debugging, but take performance...
      // **************************************************************
      boolean sv = xmlSignature.getSignatureValue().validate(valContext);
      LOG.info("signature validation status: " + sv);

    }

    // Policy is OK, now validating
    LOG.info("    ==> Signature is " + (allvalid ? "VALID" : "invalid"));
    return xmlSignature.validate(valContext);
  }

}
