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

import org.apache.log4j.Logger;
import wsattacker.library.intelligentdos.common.AttackModel;
import static wsattacker.library.intelligentdos.common.RequestType.UNTAMPERED;
import wsattacker.library.intelligentdos.helper.CommonParamItem;

/**
 * @author Christian Altmeier
 */
public abstract class AbstractDoSState
    implements DoSState
{

    protected final Logger logger = Logger.getLogger( getClass() );

    protected void setSuccessfulState( final IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        // create a new untampered attack for verification
        STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createVerifyUntampered( true ) );
        STATE_CONTEXT.setHasFurtherAttack( true );

        STATE_CONTEXT.setDoSState( new SuccessfulState() );
    }

    protected void continueAttacks( final IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        // create the next attack
        STATE_CONTEXT.setCurrentAttack( STATE_CONTEXT.createNextAttack() );

        AttackModel currentAttack = STATE_CONTEXT.getCurrentAttack();
        STATE_CONTEXT.setHasFurtherAttack( currentAttack != null );

        if ( currentAttack != null && currentAttack.getRequestType() == UNTAMPERED )
        {
            STATE_CONTEXT.setDoSState( new UntamperedState() );
        }
    }

    static void switchToFinishState( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        STATE_CONTEXT.setCurrentAttack( null );
        STATE_CONTEXT.setHasFurtherAttack( false );
        STATE_CONTEXT.setDoSState( new FinishState() );
    }

    static void createUTR( IntelligentDoSLibraryImpl STATE_CONTEXT )
    {
        AttackModel untampered = STATE_CONTEXT.createNewUntampered( true );
        setAttack( STATE_CONTEXT, untampered );
    }

    static AttackModel createTRWithParam( IntelligentDoSLibraryImpl STATE_CONTEXT, CommonParamItem paramItem )
    {
        AttackModel tampered = STATE_CONTEXT.createNewTampered( false );
        tampered.setParamItem( paramItem );

        return tampered;
    }

    static void setAttack( IntelligentDoSLibraryImpl STATE_CONTEXT, AttackModel newAttack )
    {
        STATE_CONTEXT.setCurrentAttack( newAttack );
        STATE_CONTEXT.setHasFurtherAttack( true );
    }

}
