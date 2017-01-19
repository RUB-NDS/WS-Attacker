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
package wsattacker.plugin.intelligentdos.main;

import java.io.File;

import org.apache.commons.lang3.StringUtils;

import wsattacker.plugin.intelligentdos.model.ResultModel;
import wsattacker.plugin.intelligentdos.ui.dialog.Result_NB;

/**
 * @author Christian Altmeier
 */
public class ResultMain
{

    /**
     * @param args the command line arguments
     * @throws Exception
     */
    public static void main( String args[] )
        throws Exception
    {
        if ( args.length == 0 || StringUtils.isEmpty( args[0] ) )
        {
            System.exit( -1 );
        }

        File file = new File( args[0] );
        final ResultModel resultModel = new ResultModel();
        resultModel.readIn( file );

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater( new Runnable()
        {
            @Override
            public void run()
            {
                Result_NB dialog =
                    new Result_NB( "WS-Attacker - Intelligent Denial-of-Service Attack Results", resultModel );
                dialog.addWindowListener( new java.awt.event.WindowAdapter()
                {
                    @Override
                    public void windowClosing( java.awt.event.WindowEvent e )
                    {
                        System.exit( 0 );
                    }
                } );
                dialog.setVisible( true );
            }
        } );
    }

}
