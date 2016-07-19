/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2011 Christian Mainka
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
package wsattacker.plugin.signatureWrapping.option;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import org.apache.log4j.Logger;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import wsattacker.library.signatureWrapping.option.Payload;
import wsattacker.library.signatureWrapping.util.signature.SignatureManager;
import wsattacker.library.xmlutilities.dom.DomUtilities;
import wsattacker.main.composition.plugin.option.AbstractOption;
import wsattacker.main.composition.plugin.option.AbstractOptionBoolean;
import wsattacker.main.composition.plugin.option.AbstractOptionMultiFiles;
import wsattacker.main.composition.testsuite.CurrentRequestContentChangeObserver;
import wsattacker.main.plugin.PluginOptionContainer;
import wsattacker.main.plugin.option.OptionSimpleBoolean;
import wsattacker.main.plugin.option.OptionSimpleMultiFiles;
import wsattacker.main.plugin.option.OptionSimpleVarchar;
import wsattacker.main.plugin.option.OptionSoapAction;
import wsattacker.plugin.signatureWrapping.SignatureWrapping;

/**
 * This class takes care on the options for the WS-Attacker XSW Plugin.
 */
public class OptionManager
    implements CurrentRequestContentChangeObserver, PropertyChangeListener
{

    private SignatureWrapping plugin;

    private SignatureManager signatureManager;

    private final OptionSoapAction optionSoapAction;

    private final OptionSimpleBoolean optionMustContainString, optionUseSchema, abortOnFirstSuccess;

    private final OptionSimpleVarchar optionTheContainedString;

    private final OptionSimpleMultiFiles optionSchemaFiles;

    private final OptionViewButton optionView;

    private final List<OptionPayload> optionPayloadList;

    private boolean working = false;

    private static final OptionManager INSTANCE = new OptionManager();

    public static OptionManager getInstance()
    {
        return INSTANCE;
    }

    public SignatureWrapping getPlugin()
    {
        return plugin;
    }

    public void setPlugin( SignatureWrapping plugin )
    {
        if ( this.plugin != null )
        {
            this.plugin.getPluginOptions().addPropertyChangeListener( this );
        }
        this.plugin = plugin;
        if ( plugin != null )
        {
            this.plugin.getPluginOptions().addPropertyChangeListener( this );
            this.plugin.getPluginOptions().setOptions( addConfigOptions() );
        }
    }

    public SignatureManager getSignatureManager()
    {
        return signatureManager;
    }

    public void setSignatureManager( SignatureManager signatureManager )
    {
        this.signatureManager = signatureManager;
    }

    /**
     * Initialization method.
     * 
     * @param plugin
     * @param signatureManager
     */
    private OptionManager()
    {
        this.optionSoapAction = new OptionSoapAction( "Change\nAction?", "Allows to change the SoapAction Header." );
        this.optionSchemaFiles =
            new OptionSimpleMultiFiles( "Used\nSchema\nfiles",
                                        "Set the Schema Files.\nSoap11, Soap12, WSA, WSSE, WSU, DS and XPathFilter2\nare included by default." );
        this.optionMustContainString =
            new OptionSimpleBoolean( "Search?", false, "SOAP Response must contain a specific String." );
        this.abortOnFirstSuccess =
            new OptionSimpleBoolean( "Abort?", true, "Abort after first successful attack message." );
        this.optionTheContainedString = new OptionSimpleVarchar( "Contains", "Search for this String...", 200 );
        this.optionUseSchema = new OptionSimpleBoolean( "Schema?", true, "Use XML Schema." );
        this.optionPayloadList = new ArrayList<OptionPayload>();
        this.optionView = new OptionViewButton();
        optionMustContainString.addPropertyChangeListener( AbstractOptionBoolean.PROP_ON, this );
        optionSchemaFiles.addPropertyChangeListener( AbstractOptionMultiFiles.PROP_FILES, this );
        optionUseSchema.addPropertyChangeListener( AbstractOptionBoolean.PROP_ON, this );
    }

    private Logger log()
    {
        return Logger.getLogger( getClass() );
    }

    /**
     * If the current request is changed, the SignatureManger must be notified.
     */
    @Override
    public void currentRequestContentChanged( String newContent, String oldContent )
    {
        if ( !working )
        {
            working = true;
            log().trace( "Current Request Content Changed" );
            Document domDoc;
            try
            {
                domDoc = DomUtilities.stringToDom( newContent );
            }
            catch ( SAXException e )
            {
                getSignatureManager().setDocument( null );
                working = false;
                return;
            }
            getSignatureManager().setDocument( domDoc );

            for ( int i = 0; i < optionPayloadList.size(); ++i )
            {
                OptionPayload option = optionPayloadList.get( i );
                option.removePropertyChangeListener( this );
            }
            optionPayloadList.clear();

            for ( Payload payload : getSignatureManager().getPayloads() )
            {
                payload.addPropertyChangeListener( this );
                OptionPayload newPayload = new OptionPayload( payload );
                optionPayloadList.add( newPayload );
            }
            List<AbstractOption> allOptions = addConfigOptions();
            allOptions.addAll( optionPayloadList );
            if ( plugin != null )
            {
                plugin.getPluginOptions().setOptions( allOptions );
            }
            working = false;
        }
    }

    /**
     * If no curent request is available, the SignatureManager must be notified.
     */
    @Override
    public void noCurrentRequestcontent()
    {
        if ( working )
        {
            return;
        }
        working = true;
        log().trace( "No Current Message" );
        getSignatureManager().setDocument( null );
        clearOptions();
        working = false;
    }

    /**
     * This methods add the default config options to the OptionManager. Those are: - Option for changing the
     * SOAPAction. - Option for aborting the attack if one XSW message is accepted. - Option to not use any XML Schema.
     * - Option to selected XML Schema files. - Option to add a search string. - The View Button - The Payload-Chooser
     * Combobox
     */
    private List<AbstractOption> addConfigOptions()
    {
        List<AbstractOption> result;
        if ( getPlugin() == null )
        {
            log().debug( "No plugin set?" );
            result = Collections.<AbstractOption> emptyList();
        }
        else
        {
            List<AbstractOption> newOptions = new ArrayList<AbstractOption>();
            log().info( "Adding optionSoapAction" );
            newOptions.add( 0, optionSoapAction );
            log().info( "Adding abortOnFirstSuccess" );
            newOptions.add( 1, abortOnFirstSuccess );
            log().info( "Adding optionUseSchema" );
            newOptions.add( 2, optionUseSchema );
            log().info( "Adding optionSchemaFiles" );
            newOptions.add( 3, optionSchemaFiles );
            log().info( "Adding optionMustContainString" );
            newOptions.add( 4, optionMustContainString );
            if ( optionPayloadList.size() > 0 )
            {
                log().info( "Adding View Button" );
                newOptions.add( 5, optionView );
            }
            if ( optionMustContainString.isOn() )
            {
                log().info( "Adding optionTheContainedString" );
                newOptions.add( 5, optionTheContainedString );
            }
            result = newOptions;
        }
        return result;
    }

    /**
     * This function is only needed due to a GUI Bug in WS-Attacker which does not allow to put an AbstractOption at a
     * specific position. With this function, you can pop AbstractOptions up to one specific one, than add the needed
     * Options, and afterwards re-add the popped one putOptions.
     * 
     * @param needle
     * @return
     */
    public List<AbstractOption> popOptionsUpTo( AbstractOption needle )
    {
        List<AbstractOption> result = new ArrayList<AbstractOption>();
        PluginOptionContainer container = getPlugin().getPluginOptions();
        if ( !container.contains( needle ) )
        {
            return result;
        }
        while ( container.size() > 0 )
        {
            AbstractOption last = container.getByIndex( container.size() - 1 );
            if ( last == needle )
            {
                break;
            }
            container.remove( last );
            result.add( last );
        }
        log().info( "Popped: " + result.toString() );
        return result;
    }

    /**
     * This function is only needed due to a GUI Bug in WS-Attacker which does not allow to put an AbstractOption at a
     * specific position. With this function, you can pop AbstractOptions up to one specific one, than add the needed
     * Options, and afterwards re-add the popped one putOptions.
     * 
     * @param needle
     * @return
     */
    public void putOptions( List<AbstractOption> optionList )
    {
        log().info( "Put: " + optionList.toString() );
        PluginOptionContainer container = getPlugin().getPluginOptions();
        for ( int i = optionList.size() - 1; i >= 0; --i )
        {
            container.add( optionList.get( i ) );
        }
    }

    /**
     * Clear all options consecutively.
     */
    public void clearOptions()
    {
        if ( getPlugin() == null )
        {
            log().debug( "No plugin set?" );
        }
        else
        {
            log().info( "Clearing Options.." );
            PluginOptionContainer container = getPlugin().getPluginOptions();
            while ( container.size() > 0 )
            {
                container.remove( container.getByIndex( 0 ) );
            }
        }
    }

    /**
     * Handler if an option value is changed. Changes, e.g. the concrete showed PayloadOption.
     */
    @Override
    public void propertyChange( PropertyChangeEvent pce )
    {
        PluginOptionContainer container = getPlugin().getPluginOptions();
        if ( pce.getSource() instanceof OptionPayload )
        {
            plugin.checkState();
        }
        else if ( pce.getSource() == optionMustContainString )
        {
            log().info( "option == optionMustContainString" );
            if ( optionMustContainString.isOn() && !container.contains( optionTheContainedString ) )
            {
                log().info( "true == optionMustContainString.isOn()" );
                container.add( 1 + container.indexOf( optionMustContainString ), optionTheContainedString );
            }
            else if ( container.contains( optionTheContainedString ) )
            {
                log().info( "false == optionMustContainString.isOn()" );
                container.remove( optionTheContainedString );
            }
        }
        else if ( pce.getSource() == optionSchemaFiles )
        {
            plugin.setUsedSchemaFiles( optionSchemaFiles.getFiles() );
        }
        else if ( pce.getSource() == optionUseSchema )
        {
            log().info( "Remove Schema Files Option" );
            if ( !optionUseSchema.isOn() && container.contains( optionSchemaFiles ) )
            {
                container.remove( optionSchemaFiles );
                plugin.setSchemaAnalyzerDepdingOnOption();
            }
            else if ( !container.contains( optionSchemaFiles ) )
            {
                log().info( "Add Schema Files Option" );
                container.add( 1 + container.indexOf( optionUseSchema ), optionSchemaFiles );
            }
        }
        getPlugin().checkState();
    }

    public OptionSoapAction getOptionSoapAction()
    {
        return optionSoapAction;
    }

    public AbstractOptionMultiFiles getOptionSchemaFiles()
    {
        return optionSchemaFiles;
    }

    public OptionSimpleBoolean getOptionMustContainString()
    {
        return optionMustContainString;
    }

    public OptionSimpleBoolean getOptionUseSchema()
    {
        return optionUseSchema;
    }

    public OptionSimpleBoolean getAbortOnFirstSuccess()
    {
        return abortOnFirstSuccess;
    }

    public OptionSimpleVarchar getOptionTheContainedString()
    {
        return optionTheContainedString;
    }
}
