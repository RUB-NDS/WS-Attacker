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
package wsattacker.plugin.intelligentdos.ui.helper;

import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

/**
 * @author Christian Altmeire
 */
public class JButtonStateController
    implements DocumentListener, Serializable
{

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    private final JButton button;

    private StringListValidator validator = new DefaultValidator();

    public JButtonStateController( JButton button )
    {
        this.button = button;
    }

    public void setValidator( StringListValidator validator )
    {
        if ( validator == null )
        {
            throw new IllegalArgumentException( "null is not allowed!" );
        }
        this.validator = validator;
    }

    @Override
    public void changedUpdate( DocumentEvent e )
    {
        disableIfEmpty( e );
    }

    @Override
    public void insertUpdate( DocumentEvent e )
    {
        disableIfEmpty( e );
    }

    @Override
    public void removeUpdate( DocumentEvent e )
    {
        disableIfEmpty( e );
    }

    public void disableIfEmpty( DocumentEvent e )
    {
        final Document document = e.getDocument();
        String text = "";
        try
        {
            text = document.getText( 0, document.getLength() );
        }
        catch ( BadLocationException ex )
        {
            Logger.getLogger( JButtonStateController.class.getName() ).log( Level.INFO, null, ex );
        }
        button.setEnabled( validator.isValid( text ) );
    }

}
