/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Mainka
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
package wsattacker.library.signatureWrapping.xpath.wrapping;

import java.io.*;
import java.security.KeyStore;
import java.util.*;
import org.apache.log4j.PropertyConfigurator;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.KeyInfoForTesting;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.library.xmlutilities.namespace.NamespaceConstants;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.signatureWrapping.xpath.weakness.util.WeaknessLog;

/**
 * @author christian
 */
public class DoubleEnvelopingSignature
{

    public static org.apache.log4j.Logger log;

    public static KeyStore ks;

    public static KeyInfoForTesting kift;

    public DoubleEnvelopingSignature()
    {
    }

    @BeforeClass
    public static void setUpBeforeClass()
        throws Exception
    {
        PropertyConfigurator.configure( "logging.properties" );
        // Logger
        log = org.apache.log4j.Logger.getLogger( DoubleEnvelopingSignature.class );
        // log.setLevel(org.apache.log4j.Level.INFO);
        // org.apache.log4j.Logger.getLogger("wsattacker.plugin.signaturewrapping.util.signature").setLevel(org.apache.log4j.Level.WARN);
        // org.apache.log4j.Logger.getLogger("wsattacker.plugin.signaturewrapping.test.util").setLevel(org.apache.log4j.Level.WARN);
        // org.apache.log4j.Logger.getLogger(DomUtilities.class).setLevel(org.apache.log4j.Level.WARN);
        // org.apache.log4j.Logger.getLogger(WrappingOracle.class).setLevel(org.apache.log4j.Level.WARN);
        // org.apache.log4j.Logger.getLogger("wsattacker.plugin.signatureWrapping.schema.SchemaAnalyser").setLevel(org.apache.log4j.Level.ALL);
        kift = new KeyInfoForTesting();
        ks = KeyStore.getInstance( "JKS" );
        FileInputStream keyfileInputStream;
        keyfileInputStream = new FileInputStream( kift.getKeyStoreFileName() );
        ks.load( keyfileInputStream, kift.getKeyStorePassword().toCharArray() );
    }

    @Test
    public void testDoubleEnvSig()
        throws Exception
    {
        Document doc = DomUtilities.readDocument( "src/test/resources/double_enveloped_signature.xml" );
        SignatureManager signatureManager = new SignatureManager();
        signatureManager.setDocument( doc );
        assertEquals( 2, signatureManager.getSignatureElements().size() );
        List<Payload> payloadList = signatureManager.getPayloads();
        assertEquals( 2, payloadList.size() );

        Payload outer = payloadList.get( 0 );
        Element outerElement = outer.getPayloadElement();

        assertFalse( outer.isTimestamp() );
        assertFalse( outer.hasPayload() );
        assertEquals( "Response", outerElement.getLocalName() );

        Node outerIssuer = outerElement.getElementsByTagNameNS( NamespaceConstants.URI_NS_SAML20, "Issuer" ).item( 0 );
        assertEquals( "Alice", outerIssuer.getTextContent() );
        outerIssuer.setTextContent( "ATTACKER_OUTSIDE" );
        assertTrue( outer.hasPayload() );

        Payload inner = payloadList.get( 1 );
        Element innerElement = inner.getPayloadElement();

        assertFalse( inner.isTimestamp() );
        assertFalse( inner.hasPayload() );
        assertEquals( "Assertion", inner.getPayloadElement().getLocalName() );

        Node innerIssuer = innerElement.getElementsByTagNameNS( NamespaceConstants.URI_NS_SAML20, "Issuer" ).item( 0 );
        assertEquals( "Bob", innerIssuer.getTextContent() );
        innerIssuer.setTextContent( "ATTACKER_INSIDE" );
        assertTrue( inner.hasPayload() );
        // inner.setWrapOnly(true);

        // SchemaAnalyzer schemaAnalyzer =
        // SchemaAnalyzerFactory.getInstance(SchemaAnalyzerFactory.SAML20);
        SchemaAnalyzer schemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.MINIMAL );

        WrappingOracle wrappingOracle = new WrappingOracle( doc, payloadList, schemaAnalyzer );
        int max = wrappingOracle.maxPossibilities();
        assertTrue( max > 0 );

        // for(int i=0; i<max; ++i) {
        // try {
        // System.out.println(String.format("Trying %6d of %d", i, max));
        // wrappingOracle.getPossibility(i);
        // }
        // catch ( Exception e ) {
        // fail("Failed for i="+i+": " + e.getMessage());
        // }
        // }
        Document attackDocument = null;
        attackDocument = wrappingOracle.getPossibility( 385 );
        DomUtilities.writeDocument( attackDocument, "/tmp/xsw.xml", true );

    }
}
