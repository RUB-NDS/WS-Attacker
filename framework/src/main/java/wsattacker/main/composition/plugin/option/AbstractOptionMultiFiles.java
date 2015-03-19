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
package wsattacker.main.composition.plugin.option;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import wsattacker.gui.component.pluginconfiguration.composition.OptionGUI;
import wsattacker.gui.component.pluginconfiguration.option.OptionMultiFileGUI_NB;

public abstract class AbstractOptionMultiFiles
    extends AbstractOption
{

    public static final String PROP_FILES = "files";

    List<File> files = new ArrayList<File>();

    protected AbstractOptionMultiFiles( String name, String description )
    {
        super( name, description );
    }

    public List<File> getFiles()
    {
        return Collections.unmodifiableList( files );
    }

    public String getShortValueAsString()
    {
        StringBuilder buf = new StringBuilder();
        for ( File f : files )
        {
            buf.append( f.getName() ).append( ", " );
        }
        if ( buf.length() > 2 )
        {
            buf.delete( buf.length() - 2, buf.length() );
        }
        return buf.toString();
    }

    @Override
    public String getValueAsString()
    {
        StringBuilder buf = new StringBuilder();
        for ( File f : files )
        {
            buf.append( f.toString() ).append( ", " );
        }
        if ( buf.length() > 2 )
        {
            buf.delete( buf.length() - 2, buf.length() );
        }
        return buf.toString();
    }

    /**
     * Validator for a given file. This method must be really fast, since it is used as a filter when displaying the
     * file browser.
     * 
     * @param file
     * @return valid or invalid
     */
    public abstract boolean isValid( File file );

    public boolean isValid( File[] files )
    {
        boolean valid = true;
        for ( File f : files )
        {
            if ( !isValid( f ) )
            {
                valid = false;
                break;
            }
        }
        return valid;
    }

    @Override
    public boolean isValid( String value )
    {
        boolean valid = true;
        String[] values = value.split( ", " );
        for ( String name : values )
        {
            try
            {
                new File( name );
            }
            catch ( Exception e )
            {
                valid = false;
            }
        }
        return valid;
    }

    @Override
    public void parseValue( String value )
    {
        String[] values = value.split( ", " );
        files = new ArrayList<File>();
        for ( String name : values )
        {
            try
            {
                files.add( new File( name ) );
            }
            catch ( Exception e )
            {
                files.clear();
                throw new IllegalArgumentException( e );
            }
        }
    }

    public void setFiles( List<File> files )
    {
        List<File> oldFiles = this.files;
        this.files = files;
        firePropertyChange( PROP_FILES, oldFiles, files );
    }

    public void setFilesAsArray( File[] files )
    {
        setFiles( Arrays.asList( files ) );
    }

    @Override
    public OptionGUI createOptionGUI()
    {
        return new OptionMultiFileGUI_NB( this );
    }
}
