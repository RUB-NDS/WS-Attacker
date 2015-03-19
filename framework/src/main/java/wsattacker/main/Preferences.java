/**
 * WS-Attacker - A Modular Web Services Penetration Testing Framework Copyright
 * (C) 2010 Christian Mainka
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
package wsattacker.main;

import java.io.File;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.log4j.Logger;
import org.jdesktop.beans.AbstractBean;
import wsattacker.main.config.HttpConfig;
import wsattacker.persistence.XmlPersistenceError;

/**
 * Preferences can be used for setting global options for WS-Attacker
 * 
 * @author Christian Mainka
 */
@XmlRootElement( name = "WS-Attacker-Config" )
public class Preferences
    extends AbstractBean
{

    private static final Logger LOG = Logger.getLogger( Preferences.class );

    final private static File DEFAULT_CONFIG_FILE = new File( "wsattacker_config.xml" );

    private static final Preferences preferences;

    public static final String PROP_LASTWSDL = "lastWsdl";

    public static final String PROP_CREATEOPTIONALELEMENTS = "createOptionalElements";

    public static final String PROP_HTTPCONFIG = "httpConfig";
    static
    {
        Preferences readPreferences;
        try
        {
            readPreferences = readFromDisk( DEFAULT_CONFIG_FILE );
        }
        catch ( XmlPersistenceError ex )
        {

            LOG.info( String.format( "Could not load config '%s'. Reason: %s", DEFAULT_CONFIG_FILE.getAbsoluteFile(),
                                     ex ) );
            readPreferences = new Preferences();
        }
        preferences = readPreferences;
    }

    // singleton
    public static Preferences getInstance()
    {
        return preferences;
    }

    public static Preferences readFromDisk()
        throws XmlPersistenceError
    {
        return readFromDisk( DEFAULT_CONFIG_FILE );
    }

    public static Preferences readFromDisk( File fileToLoad )
        throws XmlPersistenceError
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance( Preferences.class );
            Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            Preferences loaded = (Preferences) jaxbUnmarshaller.unmarshal( fileToLoad );
            LOG.info( String.format( "Loaded successfully config from '%s'", fileToLoad.getAbsoluteFile() ) );
            return loaded;
        }
        catch ( JAXBException ex )
        {
            throw new XmlPersistenceError( String.format( "Could not load config from File '%s'",
                                                          fileToLoad.getAbsoluteFile() ), ex );
        }
    }

    public static void saveToDisk( Preferences pref, File fileToSaveIn )
        throws XmlPersistenceError
    {
        try
        {
            JAXBContext jaxbContext = JAXBContext.newInstance( Preferences.class );
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, true );
            jaxbMarshaller.marshal( pref, fileToSaveIn );
            LOG.info( String.format( "Saved successfully config to '%s'", fileToSaveIn.getAbsoluteFile() ) );
        }
        catch ( JAXBException ex )
        {
            throw new XmlPersistenceError( String.format( "Could not save config to File '%s'",
                                                          fileToSaveIn.getAbsoluteFile() ), ex );
        }
    }

    public static void saveToDisk( File fileToSaveIn )
        throws XmlPersistenceError
    {
        saveToDisk( getInstance(), fileToSaveIn );
    }

    public static void saveToDisk()
        throws XmlPersistenceError
    {
        saveToDisk( DEFAULT_CONFIG_FILE );
    }

    private String lastWsdl = "http://localhost:8080/axis2/services/Version?wsdl";

    private boolean createOptionalElements = true;

    private HttpConfig httpConfig = new HttpConfig();

    public Preferences()
    {
    }

    public HttpConfig getHttpConfig()
    {
        return httpConfig;
    }

    public void setHttpConfig( HttpConfig httpConfig )
    {
        HttpConfig oldHttpConfig = this.httpConfig;
        this.httpConfig = httpConfig;
        firePropertyChange( PROP_HTTPCONFIG, oldHttpConfig, httpConfig );
    }

    /**
     * Get the value of lastWsdl
     * 
     * @return the value of lastWsdl
     */
    public String getLastWsdl()
    {
        return lastWsdl;
    }

    /**
     * Set the value of lastWsdl
     * 
     * @param lastWsdl new value of lastWsdl
     */
    public void setLastWsdl( String lastWsdl )
    {
        String oldLastWsdl = this.lastWsdl;
        this.lastWsdl = lastWsdl;
        firePropertyChange( PROP_LASTWSDL, oldLastWsdl, lastWsdl );
    }

    /**
     * Get the value of createOptionalElements
     * 
     * @return the value of createOptionalElements
     */
    public boolean isCreateOptionalElements()
    {
        return createOptionalElements;
    }

    /**
     * Set the value of createOptionalElements
     * 
     * @param createOptionalElements new value of createOptionalElements
     */
    public void setCreateOptionalElements( boolean createOptionalElements )
    {
        boolean oldCreateOptionalElements = this.createOptionalElements;
        this.createOptionalElements = createOptionalElements;
        firePropertyChange( PROP_CREATEOPTIONALELEMENTS, oldCreateOptionalElements, createOptionalElements );
    }

}
