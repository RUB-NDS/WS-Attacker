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
package wsattacker.library.signatureFaking;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
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
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import wsattacker.library.signatureFaking.exceptions.ConfigurationException;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @version 0.1
 */
public class XmlMessageSigner
{

    private KeyStore keyStore;

    private String keyAlias;

    private char[] password;

    private final static String DEFAULT_NAMESPACE_PREFIX = "ds";

    private String signatureNamespacePrefix;

    public XmlMessageSigner()
    {
        signatureNamespacePrefix = DEFAULT_NAMESPACE_PREFIX;
    }

    public String signMessage(String message, String signedElementId, boolean useEnvelopedTransform, String signatureParent, String signatureSibling)
            throws ConfigurationException {

        try {
        // Create a DOM XMLSignatureFactory that will be used to
            // generate the enveloped signature.
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            List<Transform> transforms = new LinkedList<>();
            if (useEnvelopedTransform) {
                transforms.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            }
            transforms.add(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                    (C14NMethodParameterSpec) null));
            Reference ref = fac.newReference(signedElementId, fac.newDigestMethod(DigestMethod.SHA1, null),
                    transforms, null, null);

            // Create the SignedInfo.
            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                    (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    Collections.singletonList(ref));

            KeyStore.PrivateKeyEntry keyEntry
                    = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(password));
            X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

            // Create the KeyInfo containing the X509Data.
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            List x509Content = new ArrayList(2);
            x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(cert);
            X509Data xd = kif.newX509Data(x509Content);
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

            // Instantiate the document to be signed.
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(message.getBytes()));

            // set explicitly all Id attributes
            setAllIdAttributesInDocument(doc, "Id");
            setAllIdAttributesInDocument(doc, "ID");

        // Create a DOMSignContext and specify the RSA PrivateKey and
            // location of the resulting XMLSignature's parent element.
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
            dsc.setDefaultNamespacePrefix(signatureNamespacePrefix);

            List<? extends Node> nl1 = DomUtilities.evaluateXPath(doc, "//*[local-name()=\"" + signatureParent + "\"]");
            List<? extends Node> nl2 = DomUtilities.evaluateXPath(doc, "//*[local-name()=\"" + signatureSibling + "\"]");
            System.out.println(nl1.get(0));
            System.out.println(nl2.get(0));
            dsc.setParent(nl1.get(0));
            dsc.setNextSibling(nl2.get(0));

            // Create the XMLSignature, but don't sign it yet.
            XMLSignature signature = fac.newXMLSignature(si, ki);

            // Marshal, generate, and sign the enveloped signature.
            signature.sign(dsc);

            String result = DomUtilities.domToString(doc);

            return result;
        } catch (IOException | InvalidAlgorithmParameterException | KeyStoreException |
                MarshalException | NoSuchAlgorithmException | ParserConfigurationException |
                SAXException | UnrecoverableEntryException | XMLSignatureException |
                XPathExpressionException e) {
            throw new ConfigurationException(e);
        }
    }

    public boolean verifyMessage( String message )
        throws SAXException, MarshalException, XMLSignatureException, XPathExpressionException
    {

        Document doc = DomUtilities.stringToDom( message );
        setAllIdAttributesInDocument( doc, "Id" );
        setAllIdAttributesInDocument( doc, "ID" );

        // Find Signature element.
        NodeList nl = doc.getElementsByTagNameNS( XMLSignature.XMLNS, "Signature" );
        if ( nl.getLength() == 0 )
        {
            throw new RuntimeException( "Cannot find Signature element" );
        }

        boolean valid = true;
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance( "DOM" );
        for ( int i = 0; i < nl.getLength(); i++ )
        {
            DOMValidateContext valContext = new DOMValidateContext( new X509KeySelector(), nl.item( i ) );

            // Unmarshal the XMLSignature.
            XMLSignature signature = fac.unmarshalXMLSignature( valContext );

            // Validate the XMLSignature.
            boolean coreValidity = signature.validate( valContext );
            System.out.println( "Signature " + i + "validity: " + coreValidity );
            if ( coreValidity == false )
            {
                valid = false;
            }
        }
        return valid;
    }

    public static void setAllIdAttributesInDocument( Document doc, String idName )
        throws XPathExpressionException
    {
        List<? extends Node> result = DomUtilities.evaluateXPath( doc, "//*/@" + idName );
        for ( int i = 0; i < result.size(); ++i )
        {
            Attr attribute = (Attr) result.get( i );
            attribute.getOwnerElement().setIdAttributeNode( attribute, true );
        }
    }

    public String getSignatureNamespacePrefix()
    {
        return signatureNamespacePrefix;
    }

    public void setSignatureNamespacePrefix( String signatureNamespacePrefix )
    {
        this.signatureNamespacePrefix = signatureNamespacePrefix;
    }

    public KeyStore getKeyStore()
    {
        return keyStore;
    }

    public void setKeyStore( KeyStore keyStore )
    {
        this.keyStore = keyStore;
    }

    public String getKeyAlias()
    {
        return keyAlias;
    }

    public void setKeyAlias( String keyAlias )
    {
        this.keyAlias = keyAlias;
    }

    public char[] getPassword()
    {
        return password;
    }

    public void setPassword( char[] password )
    {
        this.password = password;
    }

    public class X509KeySelector
        extends KeySelector
    {

        public KeySelectorResult select( KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
                                         XMLCryptoContext context )
            throws KeySelectorException
        {
            Iterator ki = keyInfo.getContent().iterator();
            while ( ki.hasNext() )
            {
                XMLStructure info = (XMLStructure) ki.next();
                if ( !( info instanceof X509Data ) )
                {
                    continue;
                }
                X509Data x509Data = (X509Data) info;
                Iterator xi = x509Data.getContent().iterator();
                while ( xi.hasNext() )
                {
                    Object o = xi.next();
                    if ( !( o instanceof X509Certificate ) )
                    {
                        continue;
                    }
                    final PublicKey key = ( (X509Certificate) o ).getPublicKey();
                    // Make sure the algorithm is compatible
                    // with the method.
                    if ( algEquals( method.getAlgorithm(), key.getAlgorithm() ) )
                    {
                        return new KeySelectorResult()
                        {
                            public Key getKey()
                            {
                                return key;
                            }
                        };
                    }
                }
            }
            throw new KeySelectorException( "No key found!" );
        }

        boolean algEquals( String algURI, String algName )
        {
            if ( ( algName.equalsIgnoreCase( "DSA" ) && algURI.equalsIgnoreCase( SignatureMethod.DSA_SHA1 ) )
                || ( algName.equalsIgnoreCase( "RSA" ) && algURI.equalsIgnoreCase( SignatureMethod.RSA_SHA1 ) ) )
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
