/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2013 Christian Altmeier
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
package wsattacker.library.intelligentdos;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import wsattacker.library.intelligentdos.common.AttackModel;
import wsattacker.library.intelligentdos.common.DoSParam;
import wsattacker.library.intelligentdos.common.RequestType;
import wsattacker.library.intelligentdos.dos.CoerciveParsing;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack.PayloadPosition;
import wsattacker.library.intelligentdos.helper.IterateModel;
import wsattacker.library.intelligentdos.position.Position;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.position.SchemaAnalyzerPositionIterator;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.schemaanalyzer.AnyElementProperties;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.library.xmlutilities.dom.DomUtilities;

/**
 * @author Christian Altmeier
 */
public class IntelligentDoSLibraryImplTest
{

    private static String xmlMessage =
        "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:axis=\"http://axis2.wsattacker\">"
            + "   <soapenv:Header/>" + "   <soapenv:Body>" + "      <axis:reverser>" + "         <!--Optional:-->"
            + "         <axis:toReverse>?</axis:toReverse>" + "      </axis:reverser>" + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    // The SchemaAnalyzer
    private final SchemaAnalyzer schemaAnalyzer = SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    private final PositionIterator positionIterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage );

    private final IntelligentDoSLibraryImpl impl = new IntelligentDoSLibraryImpl( xmlMessage, positionIterator );

    @Before
    public void before()
    {
        impl.setSuccessDecider( new SimpleSuccessDecider() );

        // one attack (CoesiveParsing) with 10-11 Tags
        CoerciveParsing coerciveParsing = new CoerciveParsing();
        IterateModel iterateModel = IterateModel.custom().startAt( 10 ).stopAt( 11 ).build();
        coerciveParsing.setNumberOfTagsIterator( iterateModel );

        impl.setAttacks( new DoSAttack[] { coerciveParsing } );

        impl.initialize();
    }

    @Test
    public void testprobes()
    {
        String content = impl.getTestProbeContent();
        assertThat( content, is( xmlMessage ) );
    }

    @Test
    public void attackModel()
    {
        AttackModel attackModel = impl.nextAttack();
        assertThat( attackModel, notNullValue() );
    }

    @Test
    public void hasFurtherAttackTest()
    {
        assertThat( impl.hasFurtherAttack(), is( true ) );
    }

    @Test
    public void withoutUpdate()
    {
        impl.hasFurtherAttack();
        impl.nextAttack();
        assertThat( impl.hasFurtherAttack(), is( false ) );
    }

    @Test
    public void hasNoFurtherAttacks()
    {
        String xmlMessage2 = "<?xml version=\"1.0\"?><Envelope><Header></Header><Body></Body></Envelope>";
        PositionIterator positionIterator = new SchemaAnalyzerPositionIterator( schemaAnalyzer, xmlMessage2 );

        IntelligentDoSLibraryImpl iDoSLibrary = new IntelligentDoSLibraryImpl( xmlMessage2, positionIterator );
        assertThat( iDoSLibrary.hasFurtherAttack(), is( false ) );
    }

    @Test
    public void noneNullContent()
    {
        impl.hasFurtherAttack();
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestContent(), notNullValue() );
    }

    @Test
    public void untamperedAttackContent()
    {
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );

        String content = attack.getRequestContent();
        assertThat( content, containsString( "<!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc -->" ) );
    }

    @Test
    public void tamperedAttackContent()
    {
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
        impl.update( attack );
        attack = impl.nextAttack();

        String content = attack.getRequestContent();

        String tr = "<x><x><x><x><x><x><x><x><x><x></x></x></x></x></x></x></x></x></x></x>";
        assertThat( content, containsString( tr ) );
    }

    @Test
    public void attackMillies()
    {
        assertThat( impl.hasFurtherAttack(), is( true ) );
        // untampered always 750
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
        assertThat( attack.getMilliesBetweenRequests(), is( 750 ) );
        impl.update( attack );

        // tampered should be 750, too
        assertThat( impl.hasFurtherAttack(), is( true ) );
        attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.TAMPERED ) );
        assertThat( attack.getMilliesBetweenRequests(), is( 750 ) );
    }

    @Test
    public void iterateMillies()
    {
        assertThat( impl.hasFurtherAttack(), is( true ) );
        // first is utr
        AttackModel nextAttack = impl.nextAttack();
        impl.update( nextAttack );

        for ( int i = 750; i >= 500; i -= 250 )
        {
            assertThat( impl.hasFurtherAttack(), is( true ) );
            AttackModel attack = impl.nextAttack();
            assertThat( attack.getMilliesBetweenRequests(), is( i ) );
            impl.update( attack );
        }
    }

    @Test
    public void untamperedFirst()
    {
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
    }

    @Test
    public void untamperedTampered()
    {
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
        impl.update( attack );
        attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.TAMPERED ) );
    }

    @Test
    public void iteration()
        throws TransformerException, SAXException
    {
        int[][] possibleCommonParams =
            { { 16, 2, 750 }, { 16, 2, 500 }, { 24, 4, 500 }, { 24, 4, 250 }, { 32, 8, 250 }, { 128, 8, 250 } };

        for ( int doSAttack = 0; doSAttack < 1; doSAttack++ )
        {
            // attack
            for ( int attackParams = 0; attackParams < 2; attackParams++ )
            {
                // param

                AttackModel attack = impl.nextAttack();
                assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
                String content = attack.getRequestContent();
                System.out.println( output( DomUtilities.stringToDom( content ) ) );
                assertThat( content,
                            containsString( "<!-- ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" ) );
                assertThat( content,
                            containsString( "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc -->" ) );
                impl.update( attack );

                String tr;
                if ( attackParams == 0 )
                {
                    tr = "<x><x><x><x><x><x><x><x><x><x></x></x></x></x></x></x></x></x></x></x>";
                }
                else
                {
                    tr = "<x><x><x><x><x><x><x><x><x><x><x></x></x></x></x></x></x></x></x></x></x></x>";
                }

                for ( int payload = 0; payload < 1; payload++ )
                {
                    // position
                    for ( int extPoint = 0; extPoint < 3; extPoint++ )
                    {
                        // extpoints
                        for ( int common = 0; common < possibleCommonParams.length; common++ )
                        {
                            // common
                            attack = impl.nextAttack();

                            content = attack.getRequestContent();

                            assertThat( attack.getRequestType(), is( RequestType.TAMPERED ) );
                            assertThat( content, containsString( tr ) );
                            assertThat( attack.getNumberOfRequests(), is( possibleCommonParams[common][0] ) );
                            assertThat( attack.getNumberOfThreads(), is( possibleCommonParams[common][1] ) );
                            assertThat( attack.getMilliesBetweenRequests(), is( possibleCommonParams[common][2] ) );

                            impl.update( attack );
                        }
                    }
                }

            }
        }
        assertThat( impl.hasFurtherAttack(), is( false ) );

        //
    }

    @Test
    public void wholeAttack()
    {
        assertThat( impl.hasFurtherAttack(), is( true ) );
        AttackModel attack = impl.nextAttack();
        assertThat( attack.getRequestType(), is( RequestType.UNTAMPERED ) );
    }

    @Test
    @Ignore
    public void printOut()
    {
        RequestType requestType = null;
        List<DoSParam<?>> currentParams = null;
        Position position = null;
        PayloadPosition payloadPosition = null;

        while ( impl.hasFurtherAttack() )
        {
            AttackModel attackModel = impl.nextAttack();
            if ( currentParams != attackModel.getDoSAttack().getCurrentParams() )
            {
                currentParams = attackModel.getDoSAttack().getCurrentParams();

                payloadPosition = null;
            }

            if ( requestType != attackModel.getRequestType() )
            {
                requestType = attackModel.getRequestType();
            }

            StringBuilder builder = new StringBuilder();
            builder.append( "\t\t" );
            if ( attackModel.getRequestType() == RequestType.TAMPERED )
            {
                if ( payloadPosition != attackModel.getPayloadPosition() )
                {
                    payloadPosition = attackModel.getPayloadPosition();
                }

                if ( !position.equals( attackModel.getPosition() ) )
                {
                    position = attackModel.getPosition();
                }

                builder.append( "\t\t" );
            }

            builder.append( attackModel.getMilliesBetweenRequests() ).append( " - " ).append( attackModel.getNumberOfThreads() ).append( " - " ).append( attackModel.getNumberOfRequests() );


            impl.update( attackModel );
        }
    }

    @Test
    public void testMatcher()
        throws TransformerException, SAXException
    {

        String domToString = createPlaceholderEnrichedXml();

        PayloadPosition[] pparray = { PayloadPosition.ELEMENT, PayloadPosition.ATTRIBUTE };

        for ( PayloadPosition payloadPosition : pparray )
        {
            Matcher matcher = Pattern.compile( Pattern.quote( payloadPosition.placeholder() ) ).matcher( domToString );
            while ( matcher.find() )
            {
                System.out.printf( "%s an Position [%d,%d]%n", matcher.group(), matcher.start(), matcher.end() );

                String pre = removePlaceholder( domToString.substring( 0, matcher.start() ) );
                String post = removePlaceholder( domToString.substring( matcher.end(), domToString.length() ) );

                String s = pre + matcher.group() + post;
            }
        }
    }

    private String removePlaceholder( String s )
    {
        return s.replaceAll( Pattern.quote( PayloadPosition.ELEMENT.placeholder() ), "" ).replaceAll( Pattern.quote( PayloadPosition.ATTRIBUTE.placeholder() ),
                                                                                                      "" );
    }

    private String output( Document toAnalyze )
        throws TransformerException
    {
        final TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature( XMLConstants.FEATURE_SECURE_PROCESSING, true );
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty( OutputKeys.INDENT, "yes" );
        transformer.setOutputProperty( "{http://xml.apache.org/xslt}indent-amount", "2" );
        // initialize StreamResult with File object to save to file
        StreamResult result = new StreamResult( new StringWriter() );
        DOMSource source = new DOMSource( toAnalyze );
        transformer.transform( source, result );
        return result.getWriter().toString();

    }

    public void testStream()
        throws IOException
    {
        PipedInputStream in = new PipedInputStream();
        PipedOutputStream out = new PipedOutputStream( in );
        new Thread( new Runnable()
        {
            @Override
            public void run()
            {

                // class1.putDataOnOutputStream(out);
            }
        } ).start();

        // class2.processDataFromInputStream(in);

        in.close();
        out.close();
    }

    /*
     * helper method
     */
    private String createPlaceholderEnrichedXml()
        throws SAXException, TransformerException
    {
        String xmlMessage2 = xmlMessage.replaceAll( "\\s{2,}", "" ).replaceAll( "\n", "" );

        Document stringToDom = DomUtilities.stringToDom( xmlMessage2 );

        // find expansion points
        Document toAnalyze = DomUtilities.stringToDom( xmlMessage2 );
        Element documentElement = toAnalyze.getDocumentElement();
        Set<AnyElementProperties> findExpansionPoint = schemaAnalyzer.findExpansionPoint( documentElement );

        // find corresponding element in an other document
        List<Element> cor = new ArrayList<Element>();
        for ( AnyElementProperties anyElementProperties : findExpansionPoint )
        {
            Element element = anyElementProperties.getDocumentElement();
            Element correspondingElement = DomUtilities.findCorrespondingElement( stringToDom, element );
            cor.add( correspondingElement );
        }

        for ( Element element : cor )
        {
            Element createElement = stringToDom.createElement( "PAYLOADELEMENT" );
            element.appendChild( createElement );

            element.setAttribute( "PAYLOAD", "PAYLOAD" );
        }

        String domToString = output( stringToDom );

        domToString = domToString.replace( "PAYLOAD=\"PAYLOAD\"", PayloadPosition.ATTRIBUTE.placeholder() );
        domToString = domToString.replace( "<PAYLOADELEMENT/>", PayloadPosition.ELEMENT.placeholder() );
        return domToString;
    }
}
