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
package wsattacker.plugin.intelligentdos;

import java.net.URL;
import java.util.List;
import javax.swing.ImageIcon;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import wsattacker.library.intelligentdos.IntelligentDoSLibrary;
import wsattacker.library.intelligentdos.IntelligentDoSLibraryImpl;
import wsattacker.library.intelligentdos.common.SuccessfulAttack;
import wsattacker.library.intelligentdos.dos.DoSAttack;
import wsattacker.library.intelligentdos.helper.CommonParamItem;
import wsattacker.library.intelligentdos.position.MatcherPositionIterator;
import wsattacker.library.intelligentdos.position.PositionIterator;
import wsattacker.library.intelligentdos.success.SimpleSuccessDecider;
import wsattacker.library.schemaanalyzer.SchemaAnalyzer;
import wsattacker.library.schemaanalyzer.SchemaAnalyzerFactory;
import wsattacker.main.composition.plugin.AbstractPlugin;
import wsattacker.main.composition.plugin.PluginFunctionInterface;
import wsattacker.main.composition.plugin.PluginObserver;
import wsattacker.main.composition.testsuite.RequestResponsePair;
import wsattacker.main.plugin.PluginState;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import static wsattacker.plugin.dos.dosExtension.abstractPlugin.AbstractDosPlugin.MESSAGE;
import wsattacker.plugin.intelligentdos.listener.PersistAttackListener;
import wsattacker.plugin.intelligentdos.option.ConfigureAttacksOption;
import wsattacker.plugin.intelligentdos.option.SchemaAnalyzerOption;
import wsattacker.plugin.intelligentdos.postanalyze.IntelligentDoSPostAnalyzeFunction;
import wsattacker.plugin.intelligentdos.requestSender.Http4RequestSenderImpl;
import wsattacker.plugin.intelligentdos.ui.DoSStatusFrame;
import wsattacker.plugin.intelligentdos.worker.IntelligentDoSWorker;

public class IntelligentDoS
    extends AbstractPlugin
    implements PluginObserver
{

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private static final Logger logger = Logger.getLogger( IntelligentDoS.class );

    private static final String NAME = "Adaptive Intelligent Denial-of-Service";

    private static final URL logoPath = IntelligentDoS.class.getResource( "/images/logo_red.png" );

    private static final String DESCRIPTION =
        "<html><p>The Adaptive Intelligent Denial-of-Service (AdIDoS) attack is a composite of various "
            + "DoS attacks. With these attack a given Web service can be fully-automatically testes for DoS weaknesses. "
            + "The following DoS attacks can be chosen and configured individually:</p><ul>"
            + "<li>CoerciveParsing</li>"
            + "<li>XML Element Count</li>"
            + "<li>XML Attribute Count</li>"
            + "<li>XML Entity Expansion</li>"
            + "<li>XML External Entity</li>"
            + "<li>Hash Collision</li>"
            + "<li>XML Overlong Names</li>"
            + "</ul><p>The common parameters adjust the agressivnes by which the Web service is tested."
            + "The selected attacks are performed fully-automatically, whereby the attack vectors are adaptively adjusted. "
            + "The Intelligent Denial-of-Service attack replaces the string $$PAYLOADELEMENT$$ and $$PAYLOADATTR$$ in the SOAP message below "
            + "successively with the attack payload. "
            + "The placeholders $$PAYLOADELEMENT$$ and $$PAYLOADATTR$$ can be set to any other position in the SOAP message.</p>"
            + "</html>";

    private static final String AUTHOR = "Christian Altmeier";

    private static final String VERSION = "1.0 / 2015-07-10";

    private static final String[] CATEGORY = new String[] { "Denial of Service" };

    // TODO [CHAL 2014-08-12] configurable?
    private static final SchemaAnalyzer schemaAnalyzer =
        SchemaAnalyzerFactory.getInstance( SchemaAnalyzerFactory.WEBSERVICE );

    private ConfigureAttacksOption configureLibraryOption;

    private OptionSimpleBoolean optionSimpleBoolean;

    private SchemaAnalyzerOption payloadPlaceholders;

    private transient IntelligentDoSLibrary intelligentDoSLibrary;

    private transient IntelligentDoSWorker doSWorker;

    private DoSStatusFrame doSStatusFrame;

    @Override
    public void initializePlugin()
    {
        setName( NAME );
        setDescription( DESCRIPTION );
        setAuthor( AUTHOR );
        setVersion( VERSION );
        setCategory( CATEGORY );
        final ImageIcon icon = new ImageIcon( logoPath );
        setIcon( icon );

        setState( PluginState.Ready );

        configureLibraryOption =
            new ConfigureAttacksOption( IntelligentDoSLibraryImpl.getAllAttacks(),
                                        IntelligentDoSLibraryImpl.COMMONPARAMS,
                                        IntelligentDoSLibraryImpl.DEFAULT_SERVER_RECOVERY,
                                        Http4RequestSenderImpl.TIMEOUT );
        getPluginOptions().add( configureLibraryOption );

        optionSimpleBoolean =
            new OptionSimpleBoolean( "Use namespaces?", false,
                                     "checked = attributes with namespace, unchecked = attributes without namespace" );
        getPluginOptions().add( optionSimpleBoolean );

        // set payload position -> Always last option
        payloadPlaceholders = new SchemaAnalyzerOption( MESSAGE, "set position of payload placeholder", schemaAnalyzer );
        getPluginOptions().add( payloadPlaceholders );
    }

    @Override
    public void clean()
    {
        // TODO is this sufficient
        setState( PluginState.Ready );
    }

    @Override
    public boolean wasSuccessful()
    {
        // successfull only server is vulnerable for one method
        // note: one point = possible server misconfiguration
        return getCurrentPoints() > 1;
    }

    @Override
    public void attackImplementationHook( RequestResponsePair original )
    {
        DoSAttack[] dosAttackArray = configureLibraryOption.getAttacks();
        final List<CommonParamItem> commonParamList = configureLibraryOption.getCommonParamList();
        int serverRecoveryTime = configureLibraryOption.getServerRecoveryTime();
        int httpConnectionTimeout = configureLibraryOption.getHttpConnectionTimeout();

        if ( optionSimpleBoolean.isOn() )
        {
            for ( DoSAttack doSAttack : dosAttackArray )
            {
                doSAttack.setUseNamespace( optionSimpleBoolean.isOn() );
            }
        }

        logger.trace( "httpConnectionTimeout: " + httpConnectionTimeout );
        Http4RequestSenderImpl.setHttpConnectionTimeout( httpConnectionTimeout );

        String xmlMessage = original.getWsdlRequest().getRequestContent();
        PositionIterator positionIterator = new MatcherPositionIterator( payloadPlaceholders.getValue() );
        intelligentDoSLibrary =
            IntelligentDoSLibraryImpl.create().withXmlMessage( xmlMessage ).withPositionIterator( positionIterator ).withAttacks( dosAttackArray ).withSuccessDecider( new SimpleSuccessDecider() ).withCommonParams( commonParamList ).withServerRecoveryTime( serverRecoveryTime ).build();

        intelligentDoSLibrary.initialize();

        doSWorker = new IntelligentDoSWorker( intelligentDoSLibrary );
        String property = System.getProperty( "persist.attack.dir" );
        if ( StringUtils.isNotEmpty( property ) )
        {
            doSWorker.addListener( new PersistAttackListener( property ) );
        }
        final IntelligentDoSPostAnalyzeFunction function = new IntelligentDoSPostAnalyzeFunction( doSWorker );

        // function to analyze the result
        setPluginFunctions( new PluginFunctionInterface[] { function } );

        addPluginObserver( this );

        doSStatusFrame = new DoSStatusFrame();
        doSStatusFrame.setVisible( true );
        doSWorker.addListener( doSStatusFrame );

        // This takes a while
        doSWorker.startAttack( original );

        doSStatusFrame.dispose();

        List<SuccessfulAttack> successfulAttacks = intelligentDoSLibrary.getSuccessfulAttacks();

        int currentPoints = (int) ( ( 100.0 / dosAttackArray.length ) * successfulAttacks.size() * 1.0 );

        if ( currentPoints >= getMaxPoints() )
        {
            setCurrentPoints( getMaxPoints() );
        }
        else
        {
            setCurrentPoints( currentPoints );
        }

    }

    @Override
    public void restoreConfiguration( AbstractPlugin plugin )
    {
        // TODO [CHAL 2014-05-28] check if this is ok
        // nothing to do
    }

    @Override
    public void currentPointsChanged( AbstractPlugin plugin, int newPoints )
    {
        // not interested
    }

    @Override
    public void pluginStateChanged( AbstractPlugin plugin, PluginState newState, PluginState oldState )
    {
        if ( plugin == this )
        {
            doSWorker.stopAttack();
            doSStatusFrame.dispose();
            // setState( PluginState.Stopped );
        }

    }

}
